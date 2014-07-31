/*
 * $Id$
 * 
 * APNs support module
 *
 * Copyright (C) 2013 Volodymyr Tarasenko
 *
 * This file is part of Kamailio, a free SIP server.
 *
 *
 */

#include <stdio.h>
#include <string.h>
#include <memory.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/select.h>
#include <sys/time.h>

#include "../../dprint.h"
#include "../../lib/srdb1/db_val.h"

#include "push_common.h"
#include "push_ssl_utils.h"
#include "push.h"
#include "apns_feedback.h"

static uint32_t notification_id = 0;

static char char2bin(const char ch)
{
    if (ch >='0' && ch <= '9')
        return ch - 0x30;

    switch(tolower(ch))
    {
        case 'a':
            return 0x0a;
        case 'b':
            return 0x0b;
        case 'c':
            return 0x0c;
        case 'd':
            return 0x0d;
        case 'e':
            return 0x0e;
        case 'f':
            return 0x0f;
    }

    return 0xff;
}
static int str2bin(const char* str, char bin[DEVICE_TOKEN_LEN_BIN])
{
    char l;
    char h;

    int i;

    if (strlen(str) != DEVICE_TOKEN_LEN_STR)
    {
        LM_ERR("Cannot handle device token: wrong length, return....\n");
        return 0;
    }

    for( i = 0; i < DEVICE_TOKEN_LEN_BIN; ++i)
    {
        h = str[2*i];
        l = str[2*i +1];
        bin[i] = (char2bin(h) << 4) + char2bin(l);
    }

    return i;
}

static int bin2str(const char* bin, size_t bin_len, char** buf)
{
    int i;
    char * b = (char*)malloc(bin_len*2+1);

    if (b == NULL)
    {
        return -1;
    }

    *buf = b;

    for(i = 0; i < bin_len; ++i)
    {
        snprintf(b, 3, "%02X", bin[i]&0xff);
        b+=2;
    }
    return 1;
}

PushServer* create_push_server(const char *cert_file, 
                               const char *cert_key, 
                               const char *cert_ca,
                               const char *fqdn,
                               uint16_t port)
{
    PushServer* server;

    server = malloc(sizeof(PushServer));
    if (server == NULL)
    {
        LM_ERR("Memory allocation failed");
        return NULL;
    }

    server->server = strdup(fqdn);

    server->port   = port;
    server->socket = -1;
    if (cert_file)
        server->cert_file = strdup(cert_file);
    else
        server->cert_file = 0;

    if (cert_key)
        server->cert_key  = strdup(cert_key);
    else
        server->cert_key  = 0;

    if (cert_ca)
        server->cert_ca   = strdup(cert_ca);
    else
        server->cert_ca   = 0;

    server->ssl = 0;
    server->ssl_ctx = 0;

    server->flags = 0;

    server->error = 0;

    server->read_timeout = 0;
    server->write_timeout = 0;

    memset(&server->dbf, sizeof(server->dbf), 0);
    server->db = NULL;

    return server;
}

void destroy_push_server(PushServer* server)
{
    if (server == NULL)
        return;

    if(server->db && server->dbf.close)
        server->dbf.close(server->db);

    ssl_shutdown(server);

    free(server->server);
    free(server->cert_file);
    free(server->cert_ca);
}

int push_check_db(PushServer* apns, const char* push_db, const char* push_table)
{
    str db_url = {0, 0};
    str table = {0, 0};

    if (apns == NULL)
    {
        return 0;
    }

    if (push_db == NULL)
    {
        return 0;
    }

    db_url.s = push_db;
    db_url.len = strlen(db_url.s);

    table.s = push_table;
    table.len = strlen(push_table);

    if ((apns->dbf.init == 0) && (db_bind_mod(&db_url, &apns->dbf)))
    {
        LM_ERR("Database module not found\n");
        return -1;
    }

    if (!DB_CAPABILITY(apns->dbf, DB_CAP_ALL))
    {
        LM_ERR("Database module does not implement all functions"
               " needed by presence module\n");
        return -1;
    }

    /* should be done prior init in each child...*/
    apns->db = apns->dbf.init(&db_url);
    if (!apns->db)
    {
        LM_ERR("Connection to database failed\n");
        return -1;
    }

    if (db_check_table_version(&apns->dbf, apns->db, &table, PUSH_TABLE_VERSION) < 0) 
    {
        LM_ERR("wrong table version for %s\n", table.s);
        return -1;
    }

    apns->dbf.close(apns->db);
    apns->db = NULL;

    return 1;
}

int push_connect_db(PushServer* apns, const char* push_db, const char* push_table, int rank)
{
    str db_url = {0, 0};
    str table = {0, 0};

    if (apns == NULL || push_db == NULL)
    {
        return 0;
    }

    db_url.s = push_db;
    db_url.len = strlen(db_url.s);

    table.s = push_table;
    table.len = strlen(push_table);

    if ((apns->dbf.init == 0) && db_bind_mod(&db_url, &apns->dbf))
    {
        LM_ERR("Database module not found\n");
        return -1;
    }

    /* this code for each child */
    if (apns->dbf.init2)
        apns->db = apns->dbf.init2(&db_url, DB_POOLING_NONE);
    else
        apns->db = apns->dbf.init(&db_url);

    if (apns->dbf.use_table(apns->db, &table) < 0)
    {
        LM_ERR( "child %d:unsuccessful use_table push_table\n", rank);
        return -1;
    }

    return 1;
}

int push_send(PushServer* apns,  const char *device_token, const char* alert, const char* call_id, int badge)
{
    APNS_Payload* payload = NULL;
    APNS_Item*    item;

    char* message;

    LM_DBG("token %s\n", device_token);
    APNS_Notification* notification = create_notification();
    if (notification == NULL)
    {
        LM_ERR("Cannot create notification\n");
        return -1;
    }
    payload = calloc(1, sizeof(APNS_Payload));
    if (payload == NULL)
    {
        LM_ERR("Cannot create payload\n");
        destroy_notification(notification);
        return -1;
    }
    payload->alert   = strdup(alert);
    payload->call_id = strdup(call_id);
    payload->badge   = badge;

    item = create_item(payload, PUSH_MAX_PRIO);
    if (item == NULL)
    {
        LM_ERR("Cannot create item\n");
        destroy_notification(notification);
        destroy_payload(payload);
        return -1;
    }
    
//    memmove(item->token, device_token, DEVICE_TOKEN_LEN);

    str2bin(device_token, item->token);

    item->identifier = ++notification_id;

    if (-1 == notification_add_item(notification, item))
    {
        LM_ERR("Cannot add item, return....\n");
        destroy_notification(notification);
        destroy_payload(payload);
        return -1;
    }
    LM_DBG("item successfuly added, make a message\n");
    message = make_push_msg(notification);
    if (message == NULL)
    {
        LM_DBG("make_push_msg failed, destroy it\n");
        destroy_notification(notification);
        LM_DBG("Return -1\n");
        return -1;
    }

    {
        char *buf;
        bin2str(message, notification->length, &buf);

        LM_DBG("Sending data to apns: [%s], length %d\n", buf, notification->length);
        free(buf);
    }

    if (-1 == send_push_data(apns, message, notification->length))
    {
        LM_ERR("Push sending failed\n");
    }

    LM_DBG("OK\n");
    free(message);
    LM_DBG("Destroy\n");
    destroy_notification(notification);

    LM_DBG("Success\n");

    return 1;
}


int push_get_device(PushServer* apns, const char* aor, const char** device_token)
{
    db_key_t query_cols[1];
    db_op_t  query_ops[1];
    db_val_t query_vals[1];

    db_key_t result_cols[1];
    db1_res_t *result = NULL;
    db_row_t *row = NULL ;   
    db_val_t *row_vals = NULL;

    str aor_key = str_init("aor");
    str device_id_key = str_init("device_id");

    if (apns == NULL)
    {
        LM_ERR("Push service was not initialed, reject push registration\n");
        return -1;
    }
    if (apns->dbf.init == NULL)
    {
        LM_ERR("Database was not initialed, reject push registration\n");
        return -1;
    }

    LM_DBG("Preparing DB request for %s\n", aor);

    query_cols[0] = &aor_key;

    query_ops[0] = OP_EQ;

    query_vals[0].type = DB1_STRING;
    query_vals[0].nul = 0;
    query_vals[0].val.string_val = aor;

    result_cols[0] = &device_id_key;

    // Update table
    if (apns->dbf.query (apns->db, query_cols, query_ops, query_vals,
                         result_cols, 1, 1, 0,  &result) < 0)
    {
        LM_ERR("Database error, cannot get push registration\n");
        goto error;
    }

    if (result == NULL )
    {
        LM_ERR("Push DB request for %s failed\n", aor);
        goto error;
    }


    if (result->n <= 0)
    {
        LM_DBG("The query in db table for push returned no result\n");
        apns->dbf.free_result(apns->db, result);
        return 0;
    }

    LM_DBG("Got DB response for %s\n", aor);
    // Take first record only
    row = &result->rows[0];
    row_vals = ROW_VALUES(row);

    *device_token = strdup((char*)row_vals[0].val.string_val);

    LM_DBG("Device token for %s is [%s]\n", aor, *device_token);

    apns->dbf.free_result(apns->db, result);

    return 1;
  error:
    if (result)
        apns->dbf.free_result(apns->db, result);

    return -1;
}


int push_register_device(PushServer* apns, const char* contact, const char *device_token)
{
#define DB_PUSH_COLUMNS 2
    db_key_t key[DB_PUSH_COLUMNS];
    db_val_t value[DB_PUSH_COLUMNS];

    int columns = DB_PUSH_COLUMNS;
    int result = 0;

    str aor_key = str_init("aor");
    str device_id_key = str_init("device_id");

    LM_DBG("Push register device for %s, token %s\n", contact, device_token);
    
    if (apns == NULL)
    {
        LM_ERR("Push service was not initialed, reject push registration\n");
        return -1;
    }

    if (apns->dbf.init == NULL)
    {
        LM_ERR("Database was not initialed, reject push registration\n");
        return -1;
    }
    
    key[0] = &aor_key;
    key[1] = &device_id_key;

    value[0].type = DB1_STRING;
    value[0].nul = 0;
    value[1].val.string_val = contact;

    value[1].type = DB1_STRING;
    value[1].nul = 0;
    value[1].val.string_val = device_token;

    LM_DBG("Push register device, dbf.insert %p, db %p\n", apns->dbf.insert_update, apns->db);

    // Update table
    result = apns->dbf.insert_update(apns->db, key, value, columns);
    if (result != 0)
    {
        LM_ERR("Database error, cannot store push registration\n");
        return -1;
    }

    LM_DBG("Push DB was updated, contact %s, token [%s], result [%d]\n",contact, device_token, result);

    return 1;
}
