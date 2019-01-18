//
// Created by caddier on 1/8/19.
//

#ifndef ANDROID_APP_TLS_TUNNEL_H
#define ANDROID_APP_TLS_TUNNEL_H
#ifdef __cplusplus
extern "C" {
#endif

#include "tun2http.h"
//#include "tlse.h"
#include "mbedtls/net.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"

#define TLS_TUNNEL_STATE_ESTABLISHED 1
#define TLS_TUNNEL_STATE_DISCONNECTED    0

#define HTTP_CONNECT_STATE_INIT 0
#define HTTP_CONNECT_STATE_SENT_REQ 1
#define HTTP_CONNECT_STATE_ESTABLISHED 2

typedef struct tls_tunnel {
    mbedtls_net_context net_context;
    mbedtls_entropy_context entropy_context;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    int socket;
    char hostname[512]; //remote host domain
    uint16_t rport ; // remote port
    char proxydomain[255]; //
    int32_t state; // 1 established. 0 disconnected
    int32_t http_state; // HTTP_CONNECT_STATE_SENT_REQ OR HTTP_CONNECT_STATE_ESTABLISHED
    time_t time;
    void *tls_context;
    struct tls_tunnel *next;
}TLS_TUNNEL;


TLS_TUNNEL * wrap_tcp_socket(int socket, char *domain, uint16_t rport);
int32_t open_tunnel(TLS_TUNNEL *tunnel);
void del_tunnel(TLS_TUNNEL *tunnel);





int32_t tunnel_send(TLS_TUNNEL *tunnel, char *data, int32_t datalen);
int32_t tunnel_recv(TLS_TUNNEL *tunnel, char *out, int32_t *outlen);
void tunnel_set_httpstate_established(TLS_TUNNEL *tunnel);










#ifdef __cplusplus
};
#endif

#endif //ANDROID_APP_TLS_TUNNEL_H
