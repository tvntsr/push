#ifndef PUSH_SSL_UTILS_H
#define PUSH_SSL_UTILS_H

enum PUSH_FLAG_VALUE
{
    ConnectEstablish = 0,
    DelayedConnect,
    NoReconnect
};


int send_push_data(const char* buffer, uint32_t length);
int establish_ssl_connection(char *cert_file, char *cert_key, char *cert_ca,
                             char *server, uint16_t port);
void ssl_shutdown();

void ssl_init();

#endif //PUSH_SSL_UTILS_H
