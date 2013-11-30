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


PushServer* create_push_server(char *cert_file, char *cert_key, char *cert_ca,
                               char *fqdn, uint16_t port)
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

    return server;
}

void destoy_push_server(PushServer* server)
{
    if (server == NULL)
        return;

    ssl_shutdown(server);

    free(server->server);
    free(server->cert_file);
    free(server->cert_ca);
}
