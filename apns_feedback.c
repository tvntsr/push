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

void run_feedback(PushServer* server)
{
    struct feedback data;
    int ret;

    char message[FEEDBACK_MSG_LEN];

    if (-1 == establish_ssl_connection(server))
    {
        destroy_push_server(server);
        LM_ERR("Cannot establish connection to feedback server\n");
        return;
    }

    do
    {
        ret = read_push_status(server, message, FEEDBACK_MSG_LEN);
        switch(ret)
        {
            case 0:
                // no data
                LM_WARN("Reset peer from feedback server, done\n");
                break;
            case -1:
                // error
                LM_ERR("Got error on feedback server, return\n");
                break;
            default:
                // print the message
                break;
        }

        memcpy(&message[0], &data.timestamp, sizeof(data.timestamp));
        memcpy(&message[0] + sizeof(data.timestamp), 
               &data.token_len, 
               sizeof(data.token_len));
        memcpy(&message[0] + sizeof(data.timestamp) + sizeof(data.token_len),
               &data.token[0], 
               TOKEN_FEEDBACK_LEN);

        LM_INFO("Feedback for request: request failed timestamp %ld, id [%32s]",
                data.timestamp,
                data.token);

    }while(ret > 0);
}
