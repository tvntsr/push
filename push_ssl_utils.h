#ifndef PUSH_SSL_UTILS_H
#define PUSH_SSL_UTILS_H

#define LOG_SSL_ERROR(err)                                           \
    do                                                               \
    {                                                                \
        while ((err = ERR_get_error())) {                            \
            LM_ERR("SSL error: %s\n", ERR_error_string(err, 0));     \
        }                                                            \
    }while(0)


int send_push_data(PushServer* server, const char* buffer, uint32_t length);
int read_push_status(PushServer* server, char* buffer, uint32_t length);
int establish_ssl_connection(PushServer* server);
void ssl_shutdown(PushServer* server);

void ssl_init();

#endif //PUSH_SSL_UTILS_H
