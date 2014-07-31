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

// prints poayload to buffer
// return 0 on success, 
// on error: 
//   -1 small buffer
//   -2 payload string too long (limit is 256 chars)
static int  print_payload_msg(APNS_Payload* payload, char* buff, size_t size);

static int  print_payload_msg(APNS_Payload* payload, char* buff, size_t size)
{
    // :TODO: only alert is used
    // CallId should be used too
    // it cannot be compound value, only message
    if (payload == NULL)
        return -1;
    if (payload->alert == NULL)
        return -1;

    int printed = snprintf(buff, size, 
//                           "{\"aps\":{\"alert\":\"%s\"},\"call-id\":\"%s\"}",
                           "{\"aps\":{\"alert\":\"%s\"}}",  
                           payload->alert);

    LM_DBG("Payload: [%s], total %d\n", buff, printed);
    return printed;
}

static int notification_add_frame(APNS_Notification* to, APNS_Frame* frame);

static APNS_Frame* create_frame(APNS_Item* item);
static void destroy_frame(APNS_Frame* );



static int print_item_msg(APNS_Item* payload, char* buff, size_t size)
{
    if (payload == NULL)
        return 0;
    if (buff == NULL)
        return 0;
    if (size == 0)
        return 0;

    if (size < DEVICE_TOKEN_LEN_BIN)
        return 0;

    int printed = DEVICE_TOKEN_LEN_BIN;
    int ret;
    uint32_t t;

    LM_DBG("print item\n");

    memmove(buff, payload->token, DEVICE_TOKEN_LEN_BIN);

    ret = print_payload_msg(payload->payload, buff+printed, size-printed);
    if (ret == 0)
        return 0;
    
    printed += ret;

    if (size < printed + sizeof(t) + sizeof(payload->expiration) + 1)
        return 0;

    t =  htonl(payload->identifier);
    memcpy(buff+printed, (char*)&t, sizeof(t));
    printed += sizeof(t);

    //t =  htonl(payload->identifier);
    memcpy(buff+printed, 
            (char*)&payload->expiration, 
            sizeof(payload->expiration));

    printed += sizeof(payload->expiration);
    buff[printed] = payload->priority;
    LM_DBG("Priority: %02X, id: %04X, printed total: %d\n", ((unsigned)payload->priority) & 0xff, payload->identifier, printed +1);
    return printed + 1;
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
    // Frame: + 1 (number) + 2 (length)
    // Total:  300
    #define FRAME_BUFFER_SIZE 300
    #define CHUNK_OFFSET 3

    if (frame == NULL)
        return NULL;

    LM_DBG("Making the frame\n");

    char * chunk = (char*)malloc(FRAME_BUFFER_SIZE);
    uint16_t l;
    if (chunk != NULL)
    {
        chunk[0] = frame->number;
        frame->length = print_item_msg(frame->data, 
                                       chunk+CHUNK_OFFSET, 
                                       FRAME_BUFFER_SIZE-CHUNK_OFFSET);
        if (frame->length == 0)
        {
            free(chunk);
            chunk = NULL;
        }
        l = htons(frame->length);
        memcpy(chunk+1, &l, sizeof(l));

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

        notification->length += frame->length + CHUNK_OFFSET;
        
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
        memmove(buffer+printed, frame->_chunk, frame->length + CHUNK_OFFSET);
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
