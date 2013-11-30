#ifndef PUSH_COMMON_H
#define PUSH_COMMON_H

#include <openssl/ssl.h>

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
};

typedef struct PushServer PushServer;

enum PUSH_FLAG_VALUE
{
    ConnectEstablish = 0,
    DelayedConnect,
    NoReconnect
};

PushServer* create_push_server(char *cert_file, char *cert_key, char *cert_ca,
                               char *server, uint16_t port);
void destroy_push_server(PushServer*);


#endif //PUSH_COMMON_H
