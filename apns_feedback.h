#ifndef PUSH_APNS_FEEDBACK_H
#define PUSH_APNS_FEEDBACK_H

struct feedback
{
#define TOKEN_FEEDBACK_LEN 32
#define FEEDBACK_MSG_LEN   38

    time_t timestamp;  /* A timestamp (as a four-byte time_t value) indicating
                          when APNs determined that the application no longer 
                          exists on the device. This value, which is in 
                          network order, represents the seconds since 12:00 
                          midnight on January 1, 1970 UTC. */

    uint16_t token_len; /* The length of the device token as a two-byte 
                            integer value in network order. */

    char token[TOKEN_FEEDBACK_LEN]; /* The device token in binary format.*/
};

void run_feedback(PushServer* server, int comm_sock);

#endif //PUSH_APNS_FEEDBACK_H
