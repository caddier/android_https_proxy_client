cmake_minimum_required(VERSION 3.4.1)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/main/cpp)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/main/cpp/mbedtls/include)

set(EXECUTABLE_OUTPUT_PATH      "${CMAKE_CURRENT_SOURCE_DIR}/src/main/assets/${ANDROID_ABI}")

add_library( # Sets the name of the library.
             tun2http

             # Sets the library as a shared library.
             SHARED

          src/main/cpp/dhcp.c
          src/main/cpp/dns.c
          src/main/cpp/icmp.c
          src/main/cpp/ip.c
          src/main/cpp/http.c
          src/main/cpp/tun2http.c
          src/main/cpp/session.c
          src/main/cpp/tcp.c
          src/main/cpp/tls.c
          src/main/cpp/udp.c
          src/main/cpp/util.c
          src/main/cpp/tlse.c
          src/main/cpp/tls_tunnel.c
          #src/main/cpp/libtomcrypt.c
          #src/main/cpp/curve25519.c
)

set(src_crypto
    src/main/cpp/mbedtls/library/aes.c
    src/main/cpp/mbedtls/library/aesni.c
    src/main/cpp/mbedtls/library/arc4.c
    src/main/cpp/mbedtls/library/aria.c
    src/main/cpp/mbedtls/library/asn1parse.c
    src/main/cpp/mbedtls/library/asn1write.c
    src/main/cpp/mbedtls/library/base64.c
    src/main/cpp/mbedtls/library/bignum.c
    src/main/cpp/mbedtls/library/blowfish.c
    src/main/cpp/mbedtls/library/camellia.c
    src/main/cpp/mbedtls/library/ccm.c
    src/main/cpp/mbedtls/library/chacha20.c
    src/main/cpp/mbedtls/library/chachapoly.c
    src/main/cpp/mbedtls/library/cipher.c
    src/main/cpp/mbedtls/library/cipher_wrap.c
    src/main/cpp/mbedtls/library/cmac.c
    src/main/cpp/mbedtls/library/ctr_drbg.c
    src/main/cpp/mbedtls/library/des.c
    src/main/cpp/mbedtls/library/dhm.c
    src/main/cpp/mbedtls/library/ecdh.c
    src/main/cpp/mbedtls/library/ecdsa.c
    src/main/cpp/mbedtls/library/ecjpake.c
    src/main/cpp/mbedtls/library/ecp.c
    src/main/cpp/mbedtls/library/ecp_curves.c
    src/main/cpp/mbedtls/library/entropy.c
    src/main/cpp/mbedtls/library/entropy_poll.c
    src/main/cpp/mbedtls/library/error.c
    src/main/cpp/mbedtls/library/gcm.c
    src/main/cpp/mbedtls/library/havege.c
    src/main/cpp/mbedtls/library/hkdf.c
    src/main/cpp/mbedtls/library/hmac_drbg.c
    src/main/cpp/mbedtls/library/md.c
    src/main/cpp/mbedtls/library/md2.c
    src/main/cpp/mbedtls/library/md4.c
    src/main/cpp/mbedtls/library/md5.c
    src/main/cpp/mbedtls/library/md_wrap.c
    src/main/cpp/mbedtls/library/memory_buffer_alloc.c
    src/main/cpp/mbedtls/library/nist_kw.c
    src/main/cpp/mbedtls/library/oid.c
    src/main/cpp/mbedtls/library/padlock.c
    src/main/cpp/mbedtls/library/pem.c
    src/main/cpp/mbedtls/library/pk.c
    src/main/cpp/mbedtls/library/pk_wrap.c
    src/main/cpp/mbedtls/library/pkcs12.c
    src/main/cpp/mbedtls/library/pkcs5.c
    src/main/cpp/mbedtls/library/pkparse.c
    src/main/cpp/mbedtls/library/pkwrite.c
    src/main/cpp/mbedtls/library/platform.c
    src/main/cpp/mbedtls/library/platform_util.c
    src/main/cpp/mbedtls/library/poly1305.c
    src/main/cpp/mbedtls/library/ripemd160.c
    src/main/cpp/mbedtls/library/rsa.c
    src/main/cpp/mbedtls/library/rsa_internal.c
    src/main/cpp/mbedtls/library/sha1.c
    src/main/cpp/mbedtls/library/sha256.c
    src/main/cpp/mbedtls/library/sha512.c
    src/main/cpp/mbedtls/library/threading.c
    src/main/cpp/mbedtls/library/timing.c
    src/main/cpp/mbedtls/library/version.c
    src/main/cpp/mbedtls/library/version_features.c
    src/main/cpp/mbedtls/library/xtea.c
)

set(src_x509
    src/main/cpp/mbedtls/library/certs.c
    src/main/cpp/mbedtls/library/pkcs11.c
    src/main/cpp/mbedtls/library/x509.c
    src/main/cpp/mbedtls/library/x509_create.c
    src/main/cpp/mbedtls/library/x509_crl.c
    src/main/cpp/mbedtls/library/x509_crt.c
    src/main/cpp/mbedtls/library/x509_csr.c
    src/main/cpp/mbedtls/library/x509write_crt.c
    src/main/cpp/mbedtls/library/x509write_csr.c
)

set(src_tls
    src/main/cpp/mbedtls/library/debug.c
    src/main/cpp/mbedtls/library/net_sockets.c
    src/main/cpp/mbedtls/library/ssl_cache.c
    src/main/cpp/mbedtls/library/ssl_ciphersuites.c
    src/main/cpp/mbedtls/library/ssl_cli.c
    src/main/cpp/mbedtls/library/ssl_cookie.c
    src/main/cpp/mbedtls/library/ssl_srv.c
    src/main/cpp/mbedtls/library/ssl_ticket.c
    src/main/cpp/mbedtls/library/ssl_tls.c
)


add_library(
    tls

    STATIC

    ${src_tls}
)

add_library(
    x509

    STATIC

    ${src_x509}
)


add_library(
    crypto

    STATIC

    ${src_crypto}
)




find_library( # Sets the name of the path variable.
          log-lib

          # Specifies the name of the NDK library that
          # you want CMake to locate.
          log )

target_link_libraries( # Specifies the target library.
                       tun2http

                       ${log-lib}
                       tls
                       x509
                       crypto

 )