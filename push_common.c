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
#include "../../locking.h"

#include "push_common.h"
#include "push_ssl_utils.h"
#include "push.h"
#include "apns_feedback.h"

#define STATUS_CMD 8

typedef struct push_queue_item
{
    uint32_t message_id;
    time_t   sent_time;
    char*    message;
    size_t   len;
} push_queue_item_t;

typedef struct node
{
    push_queue_item_t push;
    struct node* next;
    struct node* prev;
} node_t;

typedef struct push_queue
{
    node_t *head;
    node_t* last;
}push_queue_t;

static gen_lock_t* push_lock = NULL;
static push_queue_t* push_queue  = NULL;

static void init_push_queue()
{
    if (push_queue == NULL) {
        push_lock = lock_alloc();
        push_queue = calloc(1, sizeof(push_queue_t));
    }
}

/* static void destroy_push_queue() */
/* { */
/*     if (push_queue != NULL) { */
/*         push_lock = lock_alloc(); */
/*         push_queue = calloc(1, sizeof(push_queue_t)); */
/*     } */
/* } */


static void add_push_to_queue(uint32_t push_message_id, char* message, size_t len)
{
    init_push_queue();
    if (push_queue == NULL){
        return;
    }

    node_t* node = calloc(1, sizeof(node_t));
    if (node == NULL)
    {
        return; 
    }

    node->push.message_id = push_message_id;
    node->push.message = message;
    node->push.len = len;
    time(&node->push.sent_time);

    lock_get(push_lock);
    if (push_queue->last == NULL) {
        push_queue->last = node;
        push_queue->last->prev = push_queue->head;
        push_queue->head = push_queue->last;
    }
    else {
        push_queue->last->next = node;
        node->prev = push_queue->last;
        push_queue->last  = node;
    }
    lock_release(push_lock);

    return;
}

static uint32_t top_message_id()
{
    if (push_lock == 0)
        return 0;

    lock_get(push_lock);
    if (push_queue == NULL || push_queue->head == NULL) {
        lock_release(push_lock);
        return 0;
    }

    uint32_t id = push_queue->head->push.message_id;
    lock_release(push_lock);
    
    return id;
}

static time_t top_message_sent()
{
    if (push_lock == NULL)
        return 0;

    lock_get(push_lock);
    if (push_queue == NULL || push_queue->head == NULL){
        lock_release(push_lock);
        return 0;
    }

    time_t time = push_queue->head->push.sent_time;
    lock_release(push_lock);

    return time;
}


static int pop_message(uint32_t* id, char** message, size_t* len, time_t* sent)
{
    if (push_lock == NULL)
        return 0;

    lock_get(push_lock);
    if (push_queue == NULL || push_queue->head == NULL){
        lock_release(push_lock);
        return 0;
    }

    node_t* top = push_queue->head;
    push_queue->head = top->next;
    if (push_queue->head != NULL) {
        push_queue->head->prev = NULL;
    }

    lock_release(push_lock);

    if (id != NULL) {
        *id = top->push.message_id; 
    }

    if (message != NULL) {
        *message = top->push.message;
    }
    else {
        free(top->push.message);
    }

    if (len != NULL) {
        *len = top->push.len;
    }

    if (sent != NULL) {
        *sent = top->push.sent_time;
    }

    free(top);
    return 1;
}


static uint32_t get_notification_id()
{
    static volatile uint32_t notification_id = 1;
    
    uint32_t ret = atomic_add_int((volatile int *)&notification_id, 1);

    return ret;
}

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

static void resend_pushes(PushServer* server, uint32_t start)
{
    char* message;
    uint32_t id;
    size_t len;
    time_t sent;

    LM_INFO("Resending data to apns: start id %u, top id %u\n", start, top_message_id());
    while(start >= top_message_id())
    {
        if (0 == pop_message(NULL, NULL, NULL, NULL))
        {
            // nothing to send, return
            return;
        }
    }

    time_t time_start = time(NULL);

    while (time_start > top_message_sent())
    {
        if (0 == pop_message(&id, &message, &len,  &sent))
        {
            return; // No message anymore
        }

        char *buf;
        bin2str(message, len, &buf);
            
        LM_INFO("Resending data to apns: id %d, sent %lu, message [%s], length %lu\n", id, sent, buf, len);
            
        free(buf);

        if (-1 == send_push_data(server, message, len))
        {
            LM_ERR("Push sending failed\n");
        }

        LM_DBG("OK\n");
        // re-add message
        add_push_to_queue(id, message, len);
    }
}

PushServer* create_push_server(const char *cert_file, 
                               const char *cert_key, 
                               const char *cert_ca,
                               const char *fqdn,
                               uint16_t port)
{
    PushServer* server;

//    init_push_queue();

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

    memset(&server->dbf, 0, sizeof(server->dbf));
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

    db_url.s = (char*)push_db;
    db_url.len = strlen(db_url.s);

    table.s = (char*)push_table;
    table.len = strlen(push_table);

    if ((apns->dbf.init == 0) && (db_bind_mod(&db_url, &apns->dbf)))
    {
        LM_ERR("Database module not found\n");
        return -1;
    }

    if (!DB_CAPABILITY(apns->dbf, DB_CAP_ALL))
    {
        LM_ERR("Database module does not implement all functions"
               " needed by push module\n");
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

    db_url.s = (char*)push_db;
    db_url.len = strlen(db_url.s);

    table.s = (char*)push_table;
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

int push_send(PushServer* apns,  const char *device_token, const char* alert, const char* custom, int badge)
{
    APNS_Payload* payload = NULL;
    APNS_Item*    item;
    uint32_t id;

    char* message;

    if (device_token == NULL)
    {
        LM_ERR("Cannot start push, device token is NULL\n");
        return -1;
    }

    if (alert == NULL)
    {
        LM_ERR("Cannot start push, alert is NULL\n");
        return -1;
    }

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
    payload->custom_param = (custom == NULL) ? NULL : strdup(custom);
    payload->badge   = badge;

    item = create_item(payload, PUSH_MAX_PRIO);
    if (item == NULL)
    {
        LM_ERR("Cannot create item\n");
        destroy_notification(notification);
        destroy_payload(payload);
        return -1;
    }

    str2bin(device_token, item->token);

    id = item->identifier = get_notification_id();

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
//    free(message);
    add_push_to_queue(id, message, notification->length);

    LM_DBG("Destroy\n");
    destroy_notification(notification);

    LM_DBG("Success\n");

    return 1;
}


int push_get_device(PushServer* apns, const char* aor, const char** device_token, const char* tbl)
{
    str table = {0, 0};

    db_key_t query_cols[1];
    db_op_t  query_ops[1];
    db_val_t query_vals[1];

    db_key_t result_cols[1];
    db1_res_t *result = NULL;
    db_row_t *row = NULL ;   
    db_val_t *row_vals = NULL;

    str aor_key = str_init("aor");
    str device_id_key = str_init("device_id");

    table.s = (char*)tbl;
    table.len = strlen(tbl);

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

    if (apns->dbf.use_table(apns->db, &table) < 0)
    {
        LM_ERR( "unsuccessful use_table push_table\n");
        return -1;
    }

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


int push_register_device(PushServer* apns, const char* contact, const char *device_token, const str* callid, const char* tbl)
{
#define DB_PUSH_COLUMNS 3
    str table = {0, 0};

    db_key_t key[DB_PUSH_COLUMNS];
    db_val_t value[DB_PUSH_COLUMNS];

    int columns = DB_PUSH_COLUMNS;
    int result  = 0;

    str aor_key       = str_init("aor");
    str device_id_key = str_init("device_id");
    str call_id_key   = str_init("callid");

    table.s = (char*)tbl;
    table.len = strlen(tbl);

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
    key[2] = &call_id_key;

    value[0].type = DB1_STRING;
    value[0].nul = 0;
    value[0].val.string_val = contact;

    value[1].type = DB1_STRING;
    value[1].nul = 0;
    value[1].val.string_val = device_token;

    value[2].type = DB1_STR;
    value[2].nul = 0;
    value[2].val.str_val = *callid;

    LM_DBG("Push register device, table %s, dbf.insert %p, db %p\n", table.s, apns->dbf.insert_update, apns->db);

    if (apns->dbf.use_table(apns->db, &table) < 0)
    {
        LM_ERR( "unsuccessful use_table push_table\n");
        return -1;
    }

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

void push_check_status(PushServer* apns)
{
    uint32_t id = 0;

#define STATUS_LEN 6
    char *buf;
    unsigned char status_buf[STATUS_LEN];

    int err = 0;

//    LM_DBG("Check push status....");

    do
    {
        err = read_push_status(apns, (char*)status_buf, STATUS_LEN);
        switch(err)
        {
            case 0:
            {
//                LM_DBG("There is no status message");
                break;
            }
            case -1:
//                LM_DBG("There is error occured");
                break;
            default:
                break;
        }

        if (err == 0 || err == -1) {
            time_t before = time(NULL) - 2;
            
            while(before > top_message_sent())
            {
                if (0 == pop_message(NULL, NULL, NULL, NULL))
                    return;
            }
            return;
        }

        {
            bin2str((char*)status_buf, STATUS_LEN, &buf);

            LM_DBG("Got status message from apns: [%s], length %d\n", buf, STATUS_LEN);
            free(buf);
        }

        if (status_buf[0] != STATUS_CMD)
        {
            LM_ERR("Received wrong status cmd (%c), expecting '8'", status_buf[0]);
            return;
        }

        memcpy(status_buf+2, &id, sizeof(id));

        LM_INFO("Status message for %d (%u): response status: [%01x]", 
                ntohl(id), 
                id,
                status_buf[1]);


        switch( status_buf[1])
        {
            case 0: // No errors encountered
                break;
            case 1: // Processing error
            case 2: // Missing device token
            case 3: // Missing topic
            case 4: // Missing payload
            case 5: // Invalid token size
            case 6: // Invalid topic size
            case 7: // Invalid payload size
                LM_ERR("APNS push: error is critical will not resend");
                break;
            case 8: // Invalid token
                resend_pushes(apns, ntohl(id));
                break;
            case 10: // Shutdown
                
            case 255: //None (unknown)
                break;
        }
    }
    while(1);
}
