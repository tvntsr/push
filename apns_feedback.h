#ifndef PUSH_APNS_FEEDBACK_H
#define PUSH_APNS_FEEDBACK_H

struct feedback
{
    time_t Timestamp;  /* A timestamp (as a four-byte time_t value) indicating
                          when APNs determined that the application no longer 
                          exists on the device. This value, which is in 
                          network order, represents the seconds since 12:00 
                          midnight on January 1, 1970 UTC. */

    uint16_t tocken_len; /* The length of the device token as a two-byte 
                            integer value in network order. */

    char token[32];      /* The device token in binary format.*/
};


#endif //PUSH_APNS_FEEDBACK_H
