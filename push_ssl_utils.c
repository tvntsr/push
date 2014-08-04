/*
 * $Id$
 * 
 * APNs support module
 *
 * Copyright (C) 2013 Volodymyr Tarasenko
 *
 * This file is part of Kamailio, a free SIP server.
 *
 * Kamailio is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * Kamailio is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "../../dprint.h"

#include "push_common.h"
#include "push_ssl_utils.h"

#define STATUS_CMD 8

/* static int push_flag; */
/* static int  ssl_socket  = -1; */
/* static SSL* ssl = NULL; */
/* static SSL_CTX* ssl_ctx = NULL; */
static int s_server_session_id_context = 1;

struct Push_error_Item
{
    char code;
    const  char* msg;
} push_codes[] = 
{
    {0, "No errors encountered"},
    {1, "Processing error"},
    {2, "Missing device token"},
    {3, "Missing topic"},
    {4, "Missing payload"},
    {5, "Invalid token size"},
    {6, "Invalid topic size"},
    {7, "Invalid payload size"},
    {8, "Invalid token"},
    {10, "Shutdown"},
    {255, "None (unknown)"}
};

// Declaration: Static functions 
static void read_status(PushServer* server);
static int load_ssl_certs(SSL_CTX* ctx, char* cert, char* key, char* ca);
static int socket_init(const char* server, uint16_t port);
static SSL_CTX* ssl_context();
static SSL* ssl_start(int sd, SSL_CTX* ctx);
static int check_cert(SSL* s);
static int socket_destroy(PushServer* server);


static int load_ssl_certs(SSL_CTX* ctx, char* cert, char* key, char* ca)
{
    int err;
    LM_DBG("Push: loading cert from [%s]\n", cert);

    /* set the local certificate from cert file */
    //if ( SSL_CTX_use_certificate_chain_file(ctx, cert) <= 0)
    err = SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM);
    if(1 != err)
    {
        LOG_SSL_ERROR(err);
        return -1;
    }

    err = SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM);
    if(err != 1)
    {
        LOG_SSL_ERROR(err);
        return -1;
    }
    
    err = SSL_CTX_load_verify_locations(ctx, ca, 0);
    if (err != 1)
    {
        LOG_SSL_ERROR(err);
        return -1;
    }

    return 0;
}

static int socket_init(const char* server, uint16_t port)
{
    struct sockaddr_in sa;
    int sd = -1;
    int err;

    memset(&sa, 0, sizeof(struct sockaddr_in));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);

    if (!inet_aton(server, &sa.sin_addr)) {
        struct hostent *host;

        LM_DBG("resolving %s...\n", server);

        if (!(host = gethostbyname(server))) {
            LM_ERR("resolving %s failed (%s).\n", server,
                   hstrerror(h_errno));
            return -1;
        }
        memcpy(&sa.sin_addr, host->h_addr_list[0], host->h_length);
    }

    LM_ERR("Create a socket and connect it to %s:%d\n", server, port);
    /* Create a socket and connect to server using normal socket calls. */
    sd = socket (PF_INET, SOCK_STREAM, 0);
    if (sd == -1)
    {
        LM_ERR("Socket creation error\n");
        return -1;
    }
   
    err = connect(sd, (struct sockaddr*) &sa, sizeof(sa));
    if (err == -1)
    {
        LM_ERR("Socket connection error\n");
        close(sd);
        sd = -1;
    }
    return sd;
}

static SSL_CTX* ssl_context()
{
    SSL_METHOD *meth;

    SSLeay_add_ssl_algorithms();

    meth = (SSL_METHOD *)SSLv23_client_method();

    return SSL_CTX_new (meth);
}

static SSL* ssl_start(int sd, SSL_CTX* ctx)
{
    int err;

    /* Start SSL negotiation. */
    SSL* s;
    BIO *sbio;

    SSL_CTX_set_session_id_context(ctx,
                                   (void*)&s_server_session_id_context,
                                   sizeof s_server_session_id_context);

    LM_DBG("Create new ssl...\n");
    s = SSL_new (ctx);
    if (s == NULL)
    {
        return NULL;
    }

    LM_DBG("Set socket to be used with ssl...\n");
    sbio=BIO_new_socket(sd, BIO_NOCLOSE);
    SSL_set_bio(s, sbio, sbio);

    LM_DBG("SSL connect...\n");
    err = SSL_connect (s);
    LM_DBG("SSL connect done...\n");
    if ((err)==-1) { ERR_print_errors_fp(stderr); return NULL; }
    LM_DBG("SSL connect done...\n");

    return s;
}

static int check_cert(SSL* s)
{
    X509*    server_cert;
    char*    str;
    /* Following two steps are optional and not required for
       data exchange to be successful. */
    /* /\* Get the cipher - opt *\/ */
    /* printf ("SSL connection using %s\n", SSL_get_cipher (ssl)); */
  
    /* Get server's certificate (note: beware of dynamic allocation) - opt */
    server_cert = SSL_get_peer_certificate (s);
    if (server_cert == NULL)
    {
        return -1;
    }
    // check the cert:
    str = X509_NAME_oneline (X509_get_subject_name (server_cert), 0, 0);
    if (str == NULL)
    {
        return -1;
    }
    OPENSSL_free (str);

    str = X509_NAME_oneline (X509_get_issuer_name  (server_cert),0,0);
    if (str == NULL)
    {
        return -1;
    }
    OPENSSL_free (str);

    /* We could do all sorts of certificate verification stuff here before
       deallocating the certificate. */
    X509_free (server_cert);

    return 0;
}

static void read_status(PushServer* server)
{
#define STATUS_LEN 6
    char status_buf[STATUS_LEN];

//    int read_len = 0;
    int err = 0;

    uint32_t id = 0;

    err = read_push_status(server, status_buf, STATUS_LEN);
    switch(err)
    {
        case 0:
        {
            LM_DBG("There is no status message");
            return;
        }
        case -1:
            LM_DBG("There is error occured");
            return;
        default:
            break;
    }

    if (status_buf[0] != STATUS_CMD)
    {
        LM_ERR("Received wrong status cmd (%c), expecting '8'", status_buf[0]);
        return;
    }

    memcpy(status_buf+2, &id, sizeof(id));

    LM_INFO("Status message for %d: response status: [%01x]", 
            ntohl(id), 
            status_buf[1]);
}

static int socket_destroy(PushServer* server)
{
    LM_DBG("Destroy ssl socket %d\n", server->socket);
    close(server->socket);
    server->socket = -1;
    return 1;
}

// Public functions

int send_push_data(PushServer* server, const char* buffer, uint32_t length)
{
    int err = 0;
    uint32_t written = 0;
    int first_try = 1;
    
  again:
    if ((server->socket == -1) && (server->flags != NoReconnect))
        establish_ssl_connection(server);

    if (server->socket == -1)
    {

        LM_ERR("Cannot write, peer disconnected...\n");
        return -1;
    }

    while(written != length)
    {
        err = SSL_write (server->ssl, buffer + written, length - written);

        switch(SSL_get_error(server->ssl, err))
        {
            case SSL_ERROR_NONE:
                written += err;
                break;
            case SSL_ERROR_WANT_WRITE:
            case SSL_ERROR_WANT_READ:
                break;
            case SSL_ERROR_ZERO_RETURN:
                LM_ERR("Cannot write, peer disconnected, reconnect...\n");
                socket_destroy(server);
                establish_ssl_connection(server);
                break;
            default:
            {
                LM_DBG("Open SSL error, %d\n", err);
                LOG_SSL_ERROR(err);
                //SSL_get_error(server->ssl, err);
                socket_destroy(server);
                return -1;
            }
        }
    }

    read_status(server);
    if (server->socket == -1 && first_try)
    {
        first_try = 0;
        goto again;
    }

    return err;
}

void ssl_shutdown(PushServer* server)
{
    /* Clean up. */
    close (server->socket);

    if (server->ssl)
        SSL_free (server->ssl);

    if (server->ssl_ctx)
        SSL_CTX_free (server->ssl_ctx);

    server->socket = -1;
    server->ssl = NULL;
    server->ssl_ctx = NULL;
}

int establish_ssl_connection(PushServer* server)
{
    server->ssl_ctx = ssl_context();
    if (server->ssl_ctx == NULL)
    {
        LM_ERR("ssl context initialization failed\n");
        server->error = -1;
        return -1;
    }

    LM_DBG("SSL context started, looading certs if any\n");
    if (server->cert_file)
        load_ssl_certs(server->ssl_ctx, 
                       server->cert_file, 
                       server->cert_key, 
                       server->cert_ca);

    server->socket = socket_init(server->server, server->port);
    if (server->socket == -1)
    {
        server->error = errno;
        LM_ERR("cannot create socket\n");
        return -1;
    }

    LM_DBG("Push socket initialed\n"); 

    server->ssl = ssl_start(server->socket, server->ssl_ctx);
    if (server->ssl == NULL)
    {
        server->error = -1;
        LM_ERR("cannot start ssl channel\n");
        return -1;
    }

    LM_DBG("Push ssl engine started\n");

    if (check_cert(server->ssl) == -1)
    {
        server->error = -1;
        LM_ERR("cannot check ssl certs\n");

        return -1;
    }

    LM_DBG("Push ssl cert are OK, start working...\n");

    return 0;
}

void ssl_init()
{
    SSL_library_init(); 
    SSL_load_error_strings();
}

int read_push_status(PushServer* server, char* buffer, uint32_t length)
{
    return extended_read(server, -1, buffer, length);
}

int extended_read(PushServer* server,
                  int comm_sock,
                  char* buffer, uint32_t length)
{
    int read_len = 0;
    int err = 0;

    fd_set readfds;
    struct timeval timeout;

    if (server->socket == -1)
        establish_ssl_connection(server);

    while(read_len != length)
    {
        int mx;
        timeout.tv_usec = server->read_timeout;
        timeout.tv_sec = 0;

        FD_SET(server->socket, &readfds);
        if (comm_sock != -1)
        {
            FD_SET(comm_sock, &readfds);
        }
        
        mx = server->socket > comm_sock ? server->socket+1 : comm_sock +1;

        err = select(mx, &readfds, 0, 0, &timeout);
        switch(err)
        {
            case 0:
            {
                // No data, return
                LM_DBG("No data in response, skip it\n");
                return 0;
            }
            case -1:
            {
                server->error = errno;
                LM_ERR("Error (%d) occured in select, returns\n", errno);
                return -1;
            }
            default:
                break;
        }
        if (comm_sock != -1 && FD_ISSET(comm_sock, &readfds))
        {
            read(comm_sock,buffer, 1);
            return COMM_SOCK_OP;
        }

        err = SSL_read(server->ssl, buffer, length);

        switch(SSL_get_error(server->ssl, err))
        {
            case SSL_ERROR_NONE:
                read_len += err;
                if (err == 0) // peer reset?
                {
                    LM_WARN("Reset peer?\n");
                    return read_len;
                }
                break;
            case SSL_ERROR_ZERO_RETURN:
              /* End of data */
              /*   SSL_shutdown(ssl); */
                LM_WARN("SSL_ERROR_ZERO_RETURN\n");
                socket_destroy(server);
                return 0;
            case SSL_ERROR_WANT_READ:
              break;
            default:
            {
                LM_ERR("Got error in reading: %d\n", err);
                server->error = err;
                LOG_SSL_ERROR(err);
                //SSL_get_error(server->ssl, err);
                return -1;
            }

        }
    }

    return read_len;
}
