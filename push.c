#include <stdio.h>
#include <string.h>
#include <memory.h>
#include <errno.h>

#include <arpa/inet.h>

#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../../parser/parse_to.h"
#include "../../lib/cds/list.h"
#include "../../lib/srdb1/db.h"
#include "../../lib/srdb1/db_val.h"

#include "push.h"

// Create a new char* chunk.
// Return NULL in case of error
// chunk should be released by free()
static char* make_frame_msg(APNS_Frame* frame);

// print item to buffer accroding to the spec:
// id:len:item
static int print_item(char* buff_to, int item_id, char* from, size_t from_len);

// prints poayload to buffer
// return 0 on success, 
// on error: 
//   -1 small buffer
//   -2 payload string too long (limit is 256 chars)
static int  print_payload_msg(APNS_Payload* payload, char* buff, size_t size);


static int notification_add_frame(APNS_Notification* to, APNS_Frame* frame);

static APNS_Frame* create_frame(APNS_Item* item);
static void destroy_frame(APNS_Frame* );

static int  print_payload_msg(APNS_Payload* payload, char* buff, size_t size)
{
    // :TODO: only alert is used
    // CallId should be used too
    // it cannot be compound value, only message
    if (payload == NULL)
        return -1;

    if (payload->alert == NULL)
        return -1;

    int printed = payload->custom_param == NULL ?
        snprintf(buff, size, 
//                           "{\"aps\":{\"alert\":\"%s\"},\"call-id\":\"%s\"}",
                 "{\"aps\":{\"alert\":{\"body\":\"%s\"}}}",  
                 payload->alert):
        snprintf(buff, size, 
                 "{\"aps\":{\"alert\":{\"body\":\"%s\"}}, %s}",  
                 payload->alert, payload->custom_param);


    LM_DBG("Payload: [%s], total %d\n", buff, printed);
    return printed;
}

static int print_item(char* buff_to, int item_id, char* from, size_t from_len)
{
    char* ptr     = buff_to;
    char ID       = item_id & 0xff;
    uint16_t len  = htons(from_len);
    int res;

    memmove(ptr, &ID, 1);
    ptr += 1;

    memmove(ptr, &len, sizeof(len));
    ptr += sizeof(len);
    
    memmove(ptr, from, from_len);
    res = from_len + 1 + sizeof(len);

    LM_DBG("printed item %d, result len %d\n", item_id, res);    
    return res;
}

static int print_item_msg(APNS_Item* payload, char* buff, size_t size)
{
    int printed = 0;
    int ret;
    uint32_t t;
    char msg_buf[PAYLOAD_MAX_LEN + 1];

    if (payload == NULL)
        return 0;
    if (buff == NULL)
        return 0;
    if (size == 0)
        return 0;

    if (size < DEVICE_TOKEN_LEN_BIN)
        return 0;


    LM_DBG("print items\n");

    printed += print_item(buff + printed, DeviceTokenID, payload->token, DEVICE_TOKEN_LEN_BIN);

    ret = print_payload_msg(payload->payload, msg_buf, PAYLOAD_MAX_LEN);
    if (ret == 0)
        return 0;

    printed += print_item(buff + printed, PayloadID, msg_buf, ret);

    if (size < printed + sizeof(t) + sizeof(payload->expiration) + 1)
        return 0;

    t =  htonl(payload->identifier);
    printed += print_item(buff + printed, NotificationID, (char*)&t, sizeof(t));

    printed += print_item(buff + printed, ExpDateID, (char*)&payload->expiration, sizeof(payload->expiration));

    printed += print_item(buff + printed, PriorityID, (char*)&payload->priority, sizeof(payload->priority));

    LM_DBG("Priority: %02X, id: %04X, printed total: %d\n", ((unsigned)payload->priority) & 0xff, payload->identifier, printed +1);
    return printed;
}

// Create a new char* chunk.
// Return NULL in case of error
// chunk should be released by free()
static char* make_frame_msg(APNS_Frame* frame)
{
    // size of the chunk:
    // payload 256
    // token    32
    // id        4
    // expire    4
    // prio      1
    // total    297
    // Frame: + (1 (number) + 2 (length))* frame count
    // Total:  312
    #define FRAME_BUFFER_SIZE 312

    if (frame == NULL)
        return NULL;

    LM_DBG("Making the frame\n");

    char * chunk = (char*)malloc(FRAME_BUFFER_SIZE);
    if (chunk != NULL)
    {
        chunk[0] = frame->number;
        frame->length = print_item_msg(frame->data, 
                                       chunk,
                                       FRAME_BUFFER_SIZE);
        if (frame->length == 0)
        {
            free(chunk);
            chunk = NULL;
        }
    }
    if (frame->_chunk)
        free(frame->_chunk);

    frame->_chunk = chunk;

    return chunk;
}


char* make_push_msg(APNS_Notification* notification)
{
#define NOTIFICATION_COMMAND (char)2
#define NOTIFICATION_OFFSET  5

    char* buffer;
    APNS_Frame* frame = NULL;

    int printed = 0;

    uint32_t count = 1;

    if (notification == NULL)
        return NULL;

    LM_DBG("Making push message\n");
    notification->length = 0;
    frame = notification->data;

    // Calculate the buffer
    while(frame != NULL)
    {
        char* chunk = NULL;

        if (frame->number != count)
        {
            // Fixup:
            frame->number = count;
        }

        chunk = make_frame_msg(frame);
        if (chunk == NULL)
        {
            // ::FIXME::
            LM_ERR("Cannot create frame, abort push\n");
            return NULL;
        }

        notification->length += frame->length;
        
        LM_DBG("Chunk %d, length %d, total: %d\n", count, frame->length, notification->length);
        frame = frame->next;
        ++count ;
    }

    LM_DBG("Push message length calculated (%u bytes), total %d frames, printing it\n",
           notification->length, count-1);
    // Fill the buffer
    buffer = (char*)malloc(notification->length+NOTIFICATION_OFFSET);
    if (buffer == NULL)
    {
        LM_ERR("Cannot allocate memory\n");
        return NULL;
    }
    buffer[0] = NOTIFICATION_COMMAND;

    count = htonl(notification->length);
    memcpy(buffer+1, &count, sizeof(count));

    printed += NOTIFICATION_OFFSET;
    
    LM_DBG("Base header filled in, add body\n");

    frame = notification->data;
    while(frame != NULL)
    {
        LM_DBG("Adding %d frame\n", frame->number);
        memmove(buffer+printed, frame->_chunk, frame->length);
        printed += frame->length;

        frame = frame->next;
    }
    LM_DBG("Done here\n");

    notification->length+=NOTIFICATION_OFFSET;

    return buffer;
}


APNS_Notification* create_notification()
{
    APNS_Notification* notification;

    notification = (APNS_Notification*)calloc(1, sizeof(APNS_Notification));

    return notification;
}

void destroy_notification(APNS_Notification* notification)
{
    if (notification == NULL)
        return;

    destroy_frame(notification->data);

    free(notification);
}


int notification_add_item(APNS_Notification* to, APNS_Item* data)
{
    APNS_Frame* frame = create_frame(data);

    return notification_add_frame(to, frame);
}

static int notification_add_frame(APNS_Notification* to, APNS_Frame* frame)
{
    APNS_Frame* last = NULL;
    uint32_t count  = 1;

    if (to == NULL)
        return -1;

    if (frame == NULL)
        return -1;

    LM_DBG("adding the frame\n");

    if (to->data == NULL)
    {
        to->data = frame;
        to->data->number = 1;
        to->data->next = to->data->prev = NULL;
        LM_DBG("First frame\n");
        return 0;
    }

    LM_DBG("Already one exists, adding the next\n");

    while(last->next != NULL)
    {
        last = last->next;
        ++count ;
        LM_DBG("Current %d\n", count);
    }

    frame->number = count;

    DOUBLE_LINKED_LIST_ADD(to->data,last, frame);

    return 0;
}

static APNS_Frame* create_frame(APNS_Item* item)
{
    APNS_Frame* frame = (APNS_Frame*)calloc(1, sizeof(APNS_Frame));
    if (frame)
    {
        frame->data = item;
    }

    return frame;
}

static void destroy_frame(APNS_Frame* frame)
{
    APNS_Frame* last = frame;
    APNS_Frame* curr;

    while(last != NULL)
    {
        destroy_item(last->data);

        curr = last;
        last = last->next;

        if (curr->_chunk)
            free(curr->_chunk);
        free(curr);
    }
}


APNS_Item* create_item(APNS_Payload* payload, unsigned char prio)
{
    APNS_Item* item = (APNS_Item*)calloc(1, sizeof(APNS_Item));
    if (item)
    {
        item->payload = payload;
        item->priority = prio;
    }


    return item;
}

void destroy_item(APNS_Item* item)
{
    if (item == NULL)
        return;

    destroy_payload(item->payload);

    free(item);
}

void destroy_payload(APNS_Payload* payload)
{
    if (payload == NULL)
        return;


    free(payload->alert);
    free(payload->sound);
}
