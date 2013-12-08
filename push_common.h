#ifndef PUSH_COMMON_H
#define PUSH_COMMON_H

#include <openssl/ssl.h>

#define ENABLE_FEEDBACK_SERVICE

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


#endif //PUSH_COMMON_H
