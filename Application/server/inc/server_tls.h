#ifndef SERVER_TLS_H
#define SERVER_TLS_H

/**********************************************************************************
 * INCLUDES
**********************************************************************************/

#include <openssl/ssl.h>

/**********************************************************************************
 * SERVER TLS INTERFACE
**********************************************************************************/

/**
 * @fn           init_server_tls
 *
 * @brief        Initialize TLS for server entity
 * 
 * @param[out] **server_tls_ctx - Double pointer to Server TLS context
 *
 * @return       0 on success, -1 on failure
 */
extern int init_server_tls(SSL_CTX **server_tls_ctx);

/**
 * @fn           deinit_server_tls
 *
 * @brief        De-initialize TLS for server entity
 * 
 * @param[out] **server_tls_ctx - Double pointer to Server TLS context
 *
 * @return       0 on success, -1 on failure
 */
extern int deinit_server_tls(SSL_CTX *server_tls_ctx);

//extern int server_perform_tls_handshake(SSL **client_tls, const SSL_CTX **server_tls_ctx);

#endif /* SERVER_TLS_H */