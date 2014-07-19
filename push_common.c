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

#include "push_common.h"
#include "push_ssl_utils.h"


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
    /* db1_con_t *p_db = NULL; */
    /* db_func_t p_dbf; */

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
