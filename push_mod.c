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

#include "../../sr_module.h"
#include "../../trim.h"
#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../../parser/parse_to.h"
//#include "../../lib/kcore/radius.h"
//#include "../../modules/acc/acc_api.h"
#include "../../cfg/cfg_struct.h"

#include "push_mod.h"
#include "push.h"
#include "push_common.h"
#include "push_ssl_utils.h"
#include "apns_feedback.h"

MODULE_VERSION

static int mod_init(void);
static void destroy(void);
static int child_init(int rank);
//static void start_feedback_service();

static void feedback_service(int fd);
static void stop_feedback_service();

//int push_init(acc_init_info_t *inf);
//int push_send_request(struct sip_msg *req, acc_info_t *inf);

static int w_push_request(struct sip_msg *rq, const char *device_token);
static int w_push_status(struct sip_msg *rq, const char* device_token, int code);

static int push_api_fixup(void** param, int param_no);
static int free_push_api_fixup(void** param, int param_no);

//static int establish_connection();

/* ----- PUSH variables ----------- */
/*@{*/

static char *push_config = 0;
static char *apns_cert_file = 0;
static char *apns_cert_key  = 0;
static char *apns_cert_ca   = 0;
static char *apns_server = 0;
static char *apns_feedback_server = "feedback.sandbox.push.apple.com";
static char *apns_alert = "You have a call";
static int   apns_badge = -1;
static char *apns_sound = 0;
static int apns_feedback_port = 2196;
static int apns_port;
static int push_flag = 0;
static int apns_read_timeout = 100000;
static int apns_feedback_read_timeout = 500000;
///void *rh;

/*@}*/

static PushServer* apns = 0;
static uint32_t notification_id = 0;

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
	{"push_apns_rtimeout", INT_PARAM, &apns_read_timeout  },
    {"push_apns_feedback_server",   STR_PARAM, &apns_feedback_server },
	{"push_apns_feedback_port",     INT_PARAM, &apns_feedback_port   },
	{"push_apns_feedback_rtimeout", INT_PARAM, &apns_feedback_read_timeout },
	{0,0,0}
};

/* static proc_export_t procs[] = { */
/*         {"Feedback service",  0,  0, feedback_service, 1 }, */
/*         {0,0,0,0,0} */
/* }; */


struct module_exports exports= {
	"push",
	DEFAULT_DLFLAGS, /* dlopen flags */
	cmds,       /* exported functions */
	params,     /* exported params */
	0,          /* exported statistics */
	0,          /* exported MI functions */
	0,          /* exported pseudo-variables */
	0,          /* extra processes, depricated? */
	mod_init,   /* initialization module */
	0,          /* response function */
	destroy,    /* destroy function */
	child_init  /* per-child init function */
};

static int pipefd[2];

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

    apns = create_push_server(apns_cert_file, 
                              apns_cert_key, 
                              apns_cert_ca, 
                              apns_server, 
                              apns_port);
    if (NULL == apns)
    {
        LM_ERR("Cannot create push structure, failed");
        return -1;
    }

    apns->read_timeout = apns_read_timeout;

    ssl_init();

#ifdef ENABLE_FEEDBACK_SERVICE
    register_procs(1);
#endif

	if (push_config == NULL || push_config[0] == '\0')
		return 0;

    /* do all staff in child init*/

	return 0;
}


static int child_init(int rank)
{
    LM_DBG("Child Init Push module\n");

#ifdef ENABLE_FEEDBACK_SERVICE
    if (rank == PROC_MAIN) 
    {
        pid_t pid;
        if (-1 == pipe(pipefd))
        {
            LM_ERR("cannot create feedback command pipe\n");
            return -1;
        }
        
		pid = fork_process(PROC_NOCHLDINIT, "MY PROC DESCRIPTION", 1);
		if (pid < 0)
			return -1; /* error */

		if(pid == 0)
        {
			/* child */
            close(pipefd[1]);
    
			/* initialize the config framework */
			if (cfg_child_init())
            {
                LM_ERR("cfg child init failed\n");
				return -1;
            }
            LM_DBG("Start feedback server");
			feedback_service(pipefd[0]);
            
            exit(0);
		}
        close(pipefd[0]);
	}
#endif

    if (push_flag == ConnectEstablish)
        return establish_ssl_connection(apns);

	/* if (rank==PROC_INIT || rank==PROC_MAIN || rank==PROC_TCP_MAIN) */
	/* 	return 0; /\* do nothing for the main process *\/ */

	return 0;
}

static void destroy(void)
{
    LM_DBG("Push destroy\n");
#ifdef ENABLE_FEEDBACK_SERVICE
    stop_feedback_service();
#endif

    destroy_push_server(apns);


    //ssl_shutdown();
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

static int w_push_request(struct sip_msg *rq, const char *device_token)
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

static int w_push_status(struct sip_msg *rq, const char* device_token, int code)
{
    return -1;
}

static void feedback_service(int fd)
{
#define FEEDBACK_MSG_LEN 38
    char status_buf[FEEDBACK_MSG_LEN];

    int read_len = 0;
    int err = 0;

    uint32_t id = 0;

    PushServer *feedback;

    feedback = create_push_server(apns_cert_file, 
                                  apns_cert_key, 
                                  apns_cert_ca, 
                                  apns_feedback_server, 
                                  apns_feedback_port);

    if (feedback == NULL)
    {
        LM_ERR("Cannot initiale feedback service");
        return;
    }

    feedback->read_timeout = apns_feedback_read_timeout;

    run_feedback(feedback, fd);
}

static void stop_feedback_service()
{
    char cmd = 'q';
    write(pipefd[1],&cmd, 1);

    close(pipefd[1]);
}
