//
// Created by home on 1/8/19.
//

#include "tls_tunnel.h"

#ifdef __cplusplus
extern "C" {
#endif

TLS_TUNNEL *g_tunnel_list_head = NULL;





void del_tunnel(TLS_TUNNEL *tunnel) {
    TLS_TUNNEL *node = g_tunnel_list_head;
    TLS_TUNNEL *prev_node = NULL;
    while(node != NULL) {
        if(node == tunnel && node != NULL) {
             if (prev_node == NULL) {
                g_tunnel_list_head = node->next;
             } else {
                prev_node->next = node->next;
             }
             break;
        }
        prev_node = node;
        node = node->next;
    }
    mbedtls_ssl_free( &tunnel->ssl );
    mbedtls_ssl_config_free( &tunnel->conf );
    mbedtls_ctr_drbg_free( &tunnel->ctr_drbg );
    mbedtls_entropy_free( &tunnel->entropy_context );
    free(tunnel);
}


TLS_TUNNEL * wrap_tcp_socket(int socket, char *domain, uint16_t rport) {
    TLS_TUNNEL *tunnel = malloc(sizeof(TLS_TUNNEL));
    tunnel->state = TLS_TUNNEL_STATE_DISCONNECTED;
    tunnel->socket = socket;
    strcpy(tunnel->hostname, domain);
    tunnel->rport = rport;
    tunnel->net_context.fd = socket;
    tunnel->next = g_tunnel_list_head;
    g_tunnel_list_head = tunnel;
    return tunnel;
}



static void tls_debug_output( void *ctx, int level,
                      const char *file, int line, const char *str ) {
    char log[512] = {0};
    sprintf( log, "%s:%04d: %s", file, line, str );
    log_android(ANDROID_LOG_INFO, log);
}

//int mbedtls_net_send( void *ctx, const unsigned char *buf, size_t len )

int32_t send_data(void *tunnel, char *data, size_t datalen) {
    TLS_TUNNEL *tls_tunnel = (TLS_TUNNEL *) tunnel;
    int32_t send_ret = send(tls_tunnel->net_context.fd, data, datalen, 0 );
    if( send_ret <= 0 ) {
        log_android(ANDROID_LOG_ERROR, " failed  returned %d\n\n", send_ret );
        return -1;
    }
    log_android(ANDROID_LOG_INFO, "send data to sock, size %d  fd %d ", datalen, tls_tunnel->net_context.fd);
    return send_ret;
}


//int mbedtls_net_recv( void *ctx, unsigned char *buf, size_t len )
//read data from data_buffer and decrypto it . return decryptoed data to outside
int32_t read_data(void *tunnel, unsigned char *buf, size_t len) {
    TLS_TUNNEL *tls_tunnel = (TLS_TUNNEL *) tunnel;
    //log_android(ANDROID_LOG_INFO, "recv data <-- %d from fd %d ", len, tls_tunnel->net_context.fd);
    int32_t ret = 0;
    memset( buf, 0, len );
    int32_t flags = fcntl(tls_tunnel->net_context.fd, F_GETFL, 0);
    if (flags & O_NONBLOCK) {
        fcntl(tls_tunnel->net_context.fd, F_SETFL, flags & ~O_NONBLOCK);
    }
    if ( (ret = recv(tls_tunnel->net_context.fd, buf, len, 0)) <= 0 ) {
        if (errno == EAGAIN ) {
            log_android(ANDROID_LOG_ERROR, " no bytes read %d ", ret);
        }
    }
    log_android(ANDROID_LOG_DEBUG, " %d bytes readed from  fd %d ", ret, tls_tunnel->net_context.fd);
    if (len != ret) {
        log_android(ANDROID_LOG_ERROR, "read data len err %d != %d ", ret , len);
    }

    return ret;
}


int32_t tunnel_send(TLS_TUNNEL *tunnel, char *data, int32_t datalen) {
    int32_t ret = 0;
    if(tunnel->state != TLS_TUNNEL_STATE_ESTABLISHED) {
        log_android(ANDROID_LOG_ERROR, "TLS TUNNEL NOT ESTABLISHED for send");
        return -1;
    }
    while( ( ret = mbedtls_ssl_write( &tunnel->ssl, data, datalen ) ) <= 0 ) {
        if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE ) {
            log_android(ANDROID_LOG_ERROR, " failed\n  ! mbedtls_ssl_write returned %d\n\n", ret );
            break;
        }
    }
    return ret;
}

void tunnel_set_httpstate_established(TLS_TUNNEL *tunnel) {
    tunnel->http_state = HTTP_CONNECT_STATE_ESTABLISHED;
    log_android(ANDROID_LOG_INFO, "HTTP Tunnel established for %s !!!!!!", tunnel->hostname);
}



int32_t tunnel_recv(TLS_TUNNEL *tunnel, char *out, int32_t *outlen) {
    int32_t ret = 0;
    int32_t left = *outlen;
    memset( out, 0, *outlen );

   if(tunnel->state != TLS_TUNNEL_STATE_ESTABLISHED) {
        log_android(ANDROID_LOG_ERROR, "tls tunnel has not been established");
        return -1;
   }

    while(((ret = mbedtls_ssl_read( &tunnel->ssl, out, left )) < 0 )) {
        if( ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE ) {
            continue;
        } else {
            break;
        }
    }

    if( ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY ) {
        log_android(ANDROID_LOG_ERROR, "close notify error for host %s socket %d ", tunnel->hostname, tunnel->socket );
        return ret;
    }

    if( ret < 0 ) {
        log_android(ANDROID_LOG_ERROR, "failed ! mbedtls_ssl_read returned %d", ret );
        return ret;
    }
    *outlen = ret;
    log_android(ANDROID_LOG_DEBUG, "tunnel_recv, bytes total %d ", ret);
    return ret;

}


int32_t open_tunnel(TLS_TUNNEL *tunnel) {
    if ( tunnel == NULL || tunnel->socket <= 0) {
        log_android(ANDROID_LOG_ERROR, "parameter error");
        return -1;
    }
    int ret = 0;
    const char *pers = "ssl_client";
    tunnel->net_context.fd = tunnel->socket;
    mbedtls_ssl_init( &tunnel->ssl );
    mbedtls_ssl_config_init( &tunnel->conf );
    mbedtls_ctr_drbg_init( &tunnel->ctr_drbg );
    mbedtls_entropy_init( &tunnel->entropy_context );
    if( ( ret = mbedtls_ctr_drbg_seed( &tunnel->ctr_drbg, mbedtls_entropy_func, &tunnel->entropy_context,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        log_android( ANDROID_LOG_ERROR, " failed\n  ! mbedtls_ctr_drbg_seed returned %d", ret );
        return -1;
    }


    if( ( ret = mbedtls_ssl_config_defaults( &tunnel->conf,
                MBEDTLS_SSL_IS_CLIENT,
                MBEDTLS_SSL_TRANSPORT_STREAM,
                MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
    {
        log_android(ANDROID_LOG_ERROR, " failed  ! mbedtls_ssl_config_defaults returned %d\n", ret );
        return -1;
    }

    mbedtls_ssl_conf_authmode( &tunnel->conf, MBEDTLS_SSL_VERIFY_NONE );
    mbedtls_ssl_conf_rng( &tunnel->conf, mbedtls_ctr_drbg_random, &tunnel->ctr_drbg );
    mbedtls_ssl_conf_dbg( &tunnel->conf, tls_debug_output, stdout );

    //for server name check
    if( ( ret = mbedtls_ssl_set_hostname( &tunnel->ssl, tunnel->hostname ) ) != 0 )
    {
        log_android(ANDROID_LOG_ERROR, " failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret );
        return -1;
    }
    if( ( ret = mbedtls_ssl_setup( &tunnel->ssl, &tunnel->conf ) ) != 0 )
    {
        log_android(ANDROID_LOG_ERROR, " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret );
        return -1;
    }

    mbedtls_ssl_set_bio( &tunnel->ssl, &tunnel->net_context, send_data, read_data, NULL );

    while( ( ret = mbedtls_ssl_handshake( &tunnel->ssl ) ) != 0 ) {
        if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE ) {
            log_android(ANDROID_LOG_ERROR, " failed ! mbedtls_ssl_handshake returned -0x%x", -ret );
            return -1;
        }
    }

    tunnel->state = TLS_TUNNEL_STATE_ESTABLISHED;
    tunnel->http_state = HTTP_CONNECT_STATE_INIT;
    log_android(ANDROID_LOG_INFO, " tls handshake success !!!!!!!! for %s", tunnel->hostname);

    char request[512] = {0};
    sprintf(request,  "CONNECT %s:%d HTTP/1.1\r\n"
                      "Host: %s:%d\r\n"
                      "Proxy-Connection: keep-alive\r\n"
                      "User-Agent:pangolin\r\n"
                      "Proxy-Authorization: Basic cHJveHlIMUEzOmMxZHdjaFVmRXo=\r\n\r\n"
                      , tunnel->hostname, tunnel->rport, tunnel->hostname, tunnel->rport);
    log_android(ANDROID_LOG_DEBUG, "send  connect request to server %s ", request);
    ret = tunnel_send(tunnel, request, strlen(request));
    if (ret < 0) {
        log_android(ANDROID_LOG_ERROR, "send connect request failed");
        return -1;
    }
    tunnel->http_state = HTTP_CONNECT_STATE_SENT_REQ;

    return ret ;
}
















#ifdef __cplusplus
};
#endif