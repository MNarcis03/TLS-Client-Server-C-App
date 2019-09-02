/**********************************************************************************
 * HEADERS
**********************************************************************************/

#include <stdio.h>
#include <stdbool.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

/**********************************************************************************
 * INTERFACES
**********************************************************************************/

#include "server_tls.h"

/**********************************************************************************
 * LOCAL DEFINES
**********************************************************************************/

/**********************************************************************************
 * LOCAL GLOBAL VARIABLES
**********************************************************************************/

/**********************************************************************************
 * LOCAL FUNCTION DECLARATIONS
**********************************************************************************/

static int load_server_certificates(const SSL_CTX *server_tls_ctx);

/**********************************************************************************
 * GLOBAL FUNCTION DEFINITIONS
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
extern int init_server_tls(SSL_CTX **server_tls_ctx)
{
    int ret_val = -1;
    SSL_CTX *server_ssl_ctx = NULL;
    SSL_METHOD *server_ssl_method = NULL;

    do
    {
        SSL_library_init();
        OpenSSL_and_all_algorithms();
        SSL_load_error_strings();

        server_ssl_method = TLSv1_2_server_method();

        if(NULL == server_ssl_method)
        {
            printf("Error at TLSv1_2_server_method()\n");
            ERR_print_errors_fp(stderr);
            break;
        }

        server_ssl_ctx = SSL_CTX_new(server_ssl_method);

        if(NULL == server_ssl_ctx)
        {
            printf("Error at SSL_CTX_new()\n");
            ERR_print_errors_fp(stderr);
            break;
        }

        ret_val = load_server_certificates(server_ssl_ctx);

        if(-1 == ret_val)
        {
            printf("Error at load_server_certificates()\n");
            break;
        }
    } while (false);

    if(-1 == ret_val)
    {
        *server_tls_ctx = NULL;
        
        ret_val = deinit_server_tls(server_ssl_ctx);

        if(-1 == ret_val)
        {
            printf("Error at deinit_server_tls()\n");
        }

        ret_val = -1;
    }
    else
    {
        *server_tls_ctx = server_ssl_ctx;
    }

    return ret_val;
}

/**
 * @fn           deinit_server_tls
 *
 * @brief        De-initialize TLS for server entity
 * 
 * @param[out] **server_tls_ctx - Double pointer to Server TLS context
 *
 * @return       0 on success, -1 on failure
 */
extern int deinit_server_tls(SSL_CTX *server_tls_ctx)
{
    int ret_val = 0;

    if(NULL != server_tls_ctx)
    {
        SSL_CTX_free(server_tls_ctx);
    }

    return ret_val;
}

/**********************************************************************************
 * LOCAL FUNCTION DEFINITIONS
**********************************************************************************/

static int load_server_certificates(const SSL_CTX *server_tls_ctx)
{
    int ret_val = -1;
    const char *SERVER_CERT_FILE_PATH = "../cert/server_cert.pem";

    do
    {
        ret_val = SSL_CTX_use_certificate_file(server_tls_ctx, SERVER_CERT_FILE_PATH, SSL_FILETYPE_PEM);

        if(1 != ret_val)
        {
            printf("Error at SSL_CTX_use_certificate_file()\n");
            ERR_print_errors_fp(stderr);
            ret_val = -1;
            break;
        }

        ret_val = SSL_CTX_use_PrivateKey_file(server_tls_ctx, SERVER_CERT_FILE_PATH, SSL_FILETYPE_PEM);

        if(1 != ret_val)
        {
            printf("Error at SSL_CTX_use_PrivateKey_file()\n");
            ERR_print_errors_fp(stderr);
            ret_val = -1;
            break;
        }

        ret_val = SSL_CTX_check_private_key(server_tls_ctx);

        if(1 != ret_val)
        {
            printf("Error at SSL_CTX_check_private_key()\n");
            ERR_print_errors_fp(stderr);
            ret_val = -1;
            break;
        }

        ret_val = 0;
    } while(false);
    

    return ret_val;
}
