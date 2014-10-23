#ifndef _PUSH_DATA_H
#define _PUSH_DATA_H

enum ItemID
{
    DeviceTokenID  = 1,
    PayloadID      = 2,
    NotificationID = 3,
    ExpDateID      = 4,
    PriorityID     = 5
};

struct APNS_Payload
{
#define PAYLOAD_MAX_LEN 256

    char *alert; /* string or dictionary
                    If this property is included, the system displays a 
                    standard alert. You may specify a string as the value 
                    of alert or a dictionary as its value. If you specify 
                    a string, it becomes the message text of an alert with 
                    two buttons: Close and View. If the user taps View, the 
                    application is launched.

                    Alternatively, you can specify a dictionary as the value 
                    of alert.*/

    uint32_t badge; /* number, 
                       The number to display as the badge of the application
                       icon.
                       If this property is absent, the badge is not changed.
                       To remove the badge, set the value of this property to
                       0. */

    char *sound;   /* string
                      The name of a sound file in the application bundle. 
                      The sound in this file is played as an alert. If the 
                      sound file doesn’t exist or default is specified as the 
                      value, the default alert sound is played. The audio must
                      be in one of the audio data formats that are compatible 
                      with system sounds; see “Preparing Custom Alert Sounds” 
                      for details. */

    uint32_t content_available; /* number
                                   Provide this key with a value of 1 to 
                                   indicate that new content is available.
                                   This is used to support Newsstand apps and 
                                   background content downloads. */
    char* custom_param;         /* custom parameter, should be formatted json string */
};
typedef struct APNS_Payload APNS_Payload;

struct APNS_Item
{
#define DEVICE_TOKEN_LEN_STR 64
#define DEVICE_TOKEN_LEN_BIN 32

#define PUSH_MAX_PRIO 10
#define PUSH_MIN_PRIO 0

    char token[DEVICE_TOKEN_LEN_BIN];/* 32 bytes, The device token in binary form, 
                      as was registered by the device. */

    APNS_Payload* payload; /* variable length, less than or equal to 256 bytes,
                              The JSON-formatted payload.
                              The payload must not be null-terminated. */

    uint32_t identifier;/* 4 bytes,
                          An arbitrary, opaque value that identifies this 
                          notification. This identifier is used for reporting
                          errors to your server. */
    uint32_t  expiration;/* 4 bytes
                           A UNIX epoch date expressed in seconds (UTC) 
                           that identifies when the notification is no 
                           longer valid and can be discarded.

                           If this value is non-zero, APNs stores the 
                           notification tries to deliver the notification 
                           at least once. Specify zero to indicate that the 
                           notification expires immediately and that APNs 
                           should not store the notification at all. */

    unsigned char priority;/* 1 byte
                              The notification’s priority. 
                              Provide one of the following values:
                               - 10 The push message is sent immediately.
                               The push notification must trigger an alert, 
                               sound, or badge on the device. It is an error 
                               to use this priority for a push that contains 
                               only the content-available key.
                               - 5 The push message is sent at a time that 
                               conserves power on the device receiving it. */
};
typedef struct APNS_Item APNS_Item;

struct APNS_Frame
{
    unsigned char number; /* 1 byte, The item number, as listed above.*/
    uint16_t      length; /* 2 bytes, The size of the item data. */
    APNS_Item*    data;   /* variable length, The frame contains the body, 
                             structured as a series of items. */

    void*         _chunk; /* Internal data*/
    struct APNS_Frame* next, *prev;
};
typedef struct APNS_Frame APNS_Frame;

struct APNS_Notification
{
    unsigned char command; /* 1 byte,  Populate with the number 2. */
    uint32_t      length; /* 4 bytes, The size of the frame data. */
    APNS_Frame*   data;  /* variable length, The frame contains the body, 
                            structured as a series of items. */
};
typedef struct APNS_Notification APNS_Notification;

char* make_push_msg(APNS_Notification* notification);

APNS_Notification* create_notification();
void destroy_notification(APNS_Notification*);

int notification_add_item(APNS_Notification* to, APNS_Item* data);

APNS_Item* create_item(APNS_Payload* payload, unsigned char prio);
void destroy_item(APNS_Item*);

void destroy_payload(APNS_Payload*);

#endif // _PUSH_DATA_H
