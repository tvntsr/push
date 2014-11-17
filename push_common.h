#ifndef PUSH_COMMON_H
#define PUSH_COMMON_H

#include <openssl/ssl.h>

#include "../../lib/srdb1/db.h"

#define ENABLE_FEEDBACK_SERVICE

#define PUSH_TABLE_VERSION 1

struct PushServer
{
    char*    server;
    uint16_t port;

    int      socket;
 
    char*    cert_file;
    char*    cert_key;
    char*    cert_ca;

    SSL*     ssl;
    SSL_CTX* ssl_ctx;

    int      flags;

    int      error;
    
    int      read_timeout; // usec
    int      write_timeout; // usec

    db_func_t dbf;
    db1_con_t *db;
};

typedef struct PushServer PushServer;

enum PUSH_FLAG_VALUE
{
    ConnectEstablish = 0,
    DelayedConnect,
    NoReconnect
};

PushServer* create_push_server(const char *cert_file, 
                               const char *cert_key, 
                               const char *cert_ca,
                               const char *server, 
                               uint16_t port);
void destroy_push_server(PushServer*);

int push_check_db(PushServer* apns, const char* push_db, const char* push_table);

int push_connect_db(PushServer* apns, const char* push_db, const char* push_table, int rank);

int push_send(PushServer* apns,  const char *device_token, const char* alert, const char* custom, int badge);

int push_register_device(PushServer* apns, const char* contact, const char *device_token, const str* callid, const char* tbl);

int push_get_device(PushServer* apns, const char* aor, const char** device_token, const char* tbl);

void push_check_status(PushServer* apns);


#endif //PUSH_COMMON_H
