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

#include "push.h"
#include "push_common.h"
#include "push_ssl_utils.h"
#include "apns_feedback.h"

#include "../../dprint.h"

#define CHECK_FEEDBACK_TIMEOUT 3600

static int waited_sleep(int sleep_sec, int fd);
static int handle_feedback_communication(PushServer* server, int comm_sock);

void run_feedback(PushServer* server, int comm_sock)
{
    int ret;

    do
    {
        if (-1 == establish_ssl_connection(server))
        {
            LM_ERR("Cannot establish connection to feedback server\n");
            ret = waited_sleep(CHECK_FEEDBACK_TIMEOUT/2, comm_sock);
            if (ret != 0)
            {
		break;
            }
            continue;
        }
        LM_DBG("Start feedback reader\n");

        handle_feedback_communication(server, comm_sock);
        //sleep
        ret = waited_sleep(CHECK_FEEDBACK_TIMEOUT, comm_sock);
    }
    while(ret == 0);

    LM_INFO("Feedback routine done\n");

    destroy_push_server(server);
}

static int handle_feedback_communication(PushServer* server, int comm_sock)
{
    int ret;
    char message[FEEDBACK_MSG_LEN];
    struct feedback data;

    do
    {
        ret = extended_read(server, comm_sock, message, FEEDBACK_MSG_LEN);
        switch(ret)
        {
            case COMM_SOCK_OP:
                LM_INFO("Terminate feedback server, quit\n");
                return -1;
            case 0:
                // no data
                LM_WARN("Reset peer from feedback server, done\n");
                return 0;
                break;
            case -1:
                // error
                LM_ERR("Got error on feedback server, return\n");
                return -1;
            default:
                // print the message
                break;
        }

        memcpy(message, &data.timestamp, sizeof(data.timestamp));
        memcpy(message + sizeof(data.timestamp), 
               &data.token_len, 
               sizeof(data.token_len));
        memcpy(message + sizeof(data.timestamp) + sizeof(data.token_len),
               &data.token[0],
               TOKEN_FEEDBACK_LEN);
        
        LM_INFO("Feedback for request: request failed timestamp %ld, id [%32s]",
                data.timestamp,
                data.token);
    }while(ret > 0);

    return 1;
}

static int waited_sleep(int sleep_sec, int fd)
{
    int err;
    fd_set readfds;
    struct timeval timeout;
    char cmd;
//    int mx;

    timeout.tv_usec = 0;
    timeout.tv_sec = sleep_sec;

    FD_SET(fd, &readfds);

    err = select(fd + 1, &readfds, 0, 0, &timeout);
    switch(err)
    {
        case 0:
        {
            // No data, return
            return 0;
        }
        case -1:
        {
            LM_ERR("Error (%d) occured in waited sleep, returns\n", errno);
            return -1;
        }
        default:
            break;
    }

    read(fd, &cmd, 1);
    return COMM_SOCK_OP;
}
