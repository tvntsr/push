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
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>


#include "../../sr_module.h"
#include "../../trim.h"
#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../../parser/parse_to.h"
//#include "../../lib/kcore/radius.h"
//#include "../../modules/acc/acc_api.h"

#include "push_mod.h"
#include "push.h"

MODULE_VERSION

static int mod_init(void);
static void destroy(void);
static int child_init(int rank);

//int push_init(acc_init_info_t *inf);
//int push_send_request(struct sip_msg *req, acc_info_t *inf);

static int w_push_request(struct sip_msg *rq, char *device_token);
static int w_push_status(struct sip_msg *rq, char* device_token, int code);

static int push_api_fixup(void** param, int param_no);
static int free_push_api_fixup(void** param, int param_no);

static int establish_connection();

/* ----- PUSH variables ----------- */
/*@{*/

static char *push_config = 0;
static char *apns_cert_file = 0;
static char *apns_cert_key  = 0;
static char *apns_cert_ca   = 0;
static char *apns_server = 0;
static char *apns_alert = "You have a call";
static int   apns_badge = -1;
static char *apns_sound = 0;

static int  apns_port;
int push_flag = 0;
void *rh;

/*@}*/

static uint32_t notification_id = 0;


enum PUSH_FLAG_VALUE
{
    ConnectEstablish = 0,
    DelayedConnect,
    NoReconnect
};

static cmd_export_t cmds[] = {
	{"push_request", (cmd_function)w_push_request, 1,
     push_api_fixup, free_push_api_fixup,
     ANY_ROUTE},
	{0, 0, 0, 0, 0, 0}
};

static param_export_t params[] = {
	{"push_config",        STR_PARAM, &push_config        },
	{"push_flag",          INT_PARAM, &push_flag          },
    {"push_apns_cert",     STR_PARAM, &apns_cert_file     },
    {"push_apns_key",      STR_PARAM, &apns_cert_key      },
    {"push_apns_cafile",   STR_PARAM, &apns_cert_ca       },
    {"push_apns_server",   STR_PARAM, &apns_server        },
	{"push_apns_port",     INT_PARAM, &apns_port          },
	{"push_apns_alert",    STR_PARAM, &apns_alert         },
	{"push_apns_sound",    STR_PARAM, &apns_sound         },
	{"push_apns_badge",    INT_PARAM, &apns_badge         },
	{0,0,0}
};


struct module_exports exports= {
	"push",
	DEFAULT_DLFLAGS, /* dlopen flags */
	cmds,       /* exported functions */
	params,     /* exported params */
	0,          /* exported statistics */
	0,          /* exported MI functions */
	0,          /* exported pseudo-variables */
	0,          /* extra processes */
	mod_init,   /* initialization module */
	0,          /* response function */
	destroy,    /* destroy function */
	child_init  /* per-child init function */
};


static int  ssl_socket  = -1;
static SSL* ssl = NULL;
static SSL_CTX* ssl_ctx = NULL;
static int s_server_session_id_context = 1;

#define LOG_SSL_ERROR(err)                                           \
    do                                                               \
    {                                                                \
        while ((err = ERR_get_error())) {                            \
            LM_ERR("SSL error: %s\n", ERR_error_string(err, 0));     \
        }                                                            \
    }while(0)


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

    meth = SSLv23_client_method();

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
  
static int send_push_data(const char* buffer, uint32_t length)
{
    int err = 0;
    uint32_t written = 0;

    if ((ssl_socket == -1) && (push_flag != NoReconnect))
        establish_connection();

    if (ssl_socket == -1)
    {

        LM_ERR("Cannot write, peer disconnected...\n");
        return -1;
    }

    while(written != length)
    {
        err = SSL_write (ssl, buffer + written, length - written);

        switch(SSL_get_error(ssl, err))
        {
            case SSL_ERROR_NONE:
                written += err;
                break;
            default:
            {
                SSL_get_error(ssl, err);
                return -1;
            }
        }
    }
        /* if (err <= 0) */
        /* { */
        /*     LM_ERR("Peer connection closed, err %d...",  */
        /*            SSL_get_error(ssl, err)); */

        /*     /\* while((err = ERR_get_error())) { *\/ */
        /*     /\*     LM_ERR("SSL error: %s\n", ERR_error_string(err, 0)); *\/ */
        /*     /\* } *\/ */
        /*     LOG_SSL_ERROR(err); */
        /*     // closed connection? */
        /*     return -1; */
        /* } */

        /* /\* else if (err == -1) *\/ */
        /* /\* { *\/ */
        /* /\*     // what is going on? Bad error? *\/ */
        /* /\*     return -1; *\/ */
        /* /\* } *\/ */
        /* written += err; */
/*}*/

    return err;
}

static void ssl_shutdown()
{
    /* Clean up. */
    close (ssl_socket);

    SSL_free (ssl);
    SSL_CTX_free (ssl_ctx);

    ssl_socket = -1;
    ssl = NULL;
    ssl_ctx = NULL;
}

static int establish_connection()
{
    ssl_ctx = ssl_context();
    if (ssl_ctx == NULL)
    {
        LM_ERR("ssl context initialization failed\n");
        return -1;
    }

    LM_DBG("SSL context started, looading certs if any\n");
    if (apns_cert_file)
        load_ssl_certs(ssl_ctx, apns_cert_file, apns_cert_key, apns_cert_ca);

    ssl_socket = socket_init(apns_server, apns_port);
    if (ssl_socket == -1)
    {
        LM_ERR("cannot create socket\n");
        return -1;
    }

    LM_DBG("Push socket initialed\n"); 

    ssl = ssl_start(ssl_socket, ssl_ctx);
    if (ssl == NULL)
    {
        LM_ERR("cannot start ssl channel\n");
        return -1;
    }

    LM_DBG("Push ssl engine started\n");

    if (check_cert(ssl) == -1)
    {
        LM_ERR("cannot check ssl certs\n");

        return -1;
    }

    LM_DBG("Push ssl cert are OK, start working...\n");

    return 0;
}

/************************** SIP helper functions ****************************/
static int
get_callid(struct sip_msg* msg, str *cid)
{
    if (msg->callid == NULL) {
        if (parse_headers(msg, HDR_CALLID_F, 0) == -1) {
            LM_ERR("cannot parse Call-ID header\n");
            return -1;
        }
        if (msg->callid == NULL) {
            LM_ERR("missing Call-ID header\n");
            return -1;
        }
    }

    *cid = msg->callid->body;

    trim(cid);

    return 0;
}


/************************** INTERFACE functions ****************************/

static int mod_init( void )
{
    LM_DBG("Init Push module\n");

    SSL_library_init(); 
    SSL_load_error_strings();

	if (push_config==NULL || push_config[0]=='\0')
		return 0;

    /* do all staff in child init*/

	return 0;
}


static int child_init(int rank)
{
    LM_DBG("Child Init Push module\n");

    if (push_flag == ConnectEstablish)
        return establish_connection();

	/* if (rank==PROC_INIT || rank==PROC_MAIN || rank==PROC_TCP_MAIN) */
	/* 	return 0; /\* do nothing for the main process *\/ */

	return 0;
}

static void destroy(void)
{
    LM_DBG("Push destroy\n");
    ssl_shutdown();
}

static int push_api_fixup(void** param, int param_no)
{
	char *p;

    LM_DBG("Push push_api_fixup\n");

	p = (char*)*param;
	if (p==0 || p[0]==0) {
		LM_ERR("first parameter is empty\n");
		return E_SCRIPT;
	}

	return 0;
}

static int free_push_api_fixup(void** param, int param_no)
{
    LM_DBG("Push free_push_api_fixup\n");
	/* if(*param) */
	/* { */
	/* 	pkg_free(*param); */
	/* 	*param = 0; */
	/* } */

    return 0;
}

static int w_push_request(struct sip_msg *rq, char *device_token)
{
    APNS_Payload* payload = NULL;
    APNS_Item*    item;
//    APNS_Frame*   frame;

    char* message;

    str *ruri;
    str  callid;
    size_t token_len = strlen(device_token);

    LM_DBG("Push request started, token %s\n", device_token);
    if (token_len != DEVICE_TOKEN_LEN)
    {
        LM_ERR("Device token length wrong, reject push\n");
        return -1;
    }

    // Working with sip message:
    ruri = GET_RURI(rq);
    if (-1 == get_callid(rq, &callid))
    {
        LM_ERR("Geting CallID failed, reject push\n");
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
    payload->alert = strdup(apns_alert);
    payload->call_id = strdup(callid.s);
    payload->badge  = apns_badge;

    item = create_item(payload);
    if (item == NULL)
    {
        LM_ERR("Cannot create item\n");
        destroy_notification(notification);
        destroy_payload(payload);
        return -1;
    }
    
    memmove(item->token, device_token, DEVICE_TOKEN_LEN);
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

    LM_DBG("Sending data to apns\n");

    if (-1 == send_push_data(message, notification->length))
    {
        LM_ERR("Push sending failed\n");
    }

    LM_DBG("OK\n");
    free(message);
    LM_DBG("Destroy\n");
    destroy_notification(notification);

    LM_DBG("Success\n");
    return 0;
}

static int w_push_status(struct sip_msg *rq, char* device_token, int code)
{
    return -1;
}

