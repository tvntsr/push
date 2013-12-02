#ifndef PUSH_SSL_UTILS_H
#define PUSH_SSL_UTILS_H

int send_push_data(PushServer* server, const char* buffer, uint32_t length);
int read_push_status(PushServer* server, char* buffer, uint32_t length);
int establish_ssl_connection(PushServer* server);
void ssl_shutdown(PushServer* server);

void ssl_init();

#endif //PUSH_SSL_UTILS_H
