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


#define FEEDBACK_MSG_LEN 38


void read_feedback(PushServer* server)
{
    struct feedback data;

    time_t tm;
    char message[FEEDBACK_MSG_LEN];


    establish_ssl_connection(server);

    if (server->error == -1)
    {
        destroy_push_server(server);
        return;
    }

    
    server->error = read_status(server, message, FEEDBACK_MSG_LEN);
    switch(server->error)
    {
        case 0:
            // no data
            break;
        case -1:
            // error
            break;
        default:
            // print the message
            break;
    }


}
