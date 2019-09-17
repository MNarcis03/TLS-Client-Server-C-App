/**********************************************************************************
 * HEADERS
**********************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

/**********************************************************************************
 * INTERFACES
**********************************************************************************/

#include "server.h"

/**********************************************************************************
 * LOCAL DEFINES
**********************************************************************************/

#define RUNNING 1
#define STOPPED 0
#define SELECT_TIMEOUT_SEC 5

/**********************************************************************************
 * LOCAL GLOBAL VARIABLES
**********************************************************************************/

static int      g_server_sock    = -1;
static int      g_server_status  = STOPPED;
static SSL_CTX *g_server_ssl_ctx = NULL;

/**********************************************************************************
 * LOCAL FUNCTION DECLARATIONS
**********************************************************************************/

static int   register_to_signals       (void);
static void  signal_handler_cb         (const int signal);
static int   disable_signals           (void);
static int   init_client               (const int client_sock);
static int   deinit_client             (const int client_sock);
static void *client_handler_thread_func(const void *arg);
static int   init_server_tls           (void);
static int   deinit_server_tls         (void);
static int   load_server_certificates  (void);
static int   perform_tls_handshake     (const int client_sock, SSL **client_ssl_struct);

/**********************************************************************************
 * GLOBAL FUNCTION DEFINITIONS
**********************************************************************************/

/**
 * @brief     Initialize server entity
 *
 * @param[in] num_of_args - Number of Command Line Arguments
 * @param[in] args - Arguments Array
 *
 * @return    0 on success, -1 on failure
 */
extern int init_server(const int num_of_args, const char *args[])
{
    int ret_val = -1;
    int port = -1;
    int read_opt = 1;
    struct sockaddr_in server_struct = {0};
    const int MAX_NUM_OF_CLIENTS = 100;
    const int NUM_OF_CMD_LINE_ARGS = 3;
    const int BIN_INDEX = 0;
    const int ADDR_INDEX = 1;
    const int PORT_INDEX = 2;

    do
    {
        if(-1 != g_server_sock)
        {
            printf("Invalid data: g_client_sock\n");
            break;
        }

        if(NUM_OF_CMD_LINE_ARGS != num_of_args)
        {
            printf("Invalid command line arguments. Proper syntax: %s <SERVER_ADRESS> <SERVER_PORT>\n", args[BIN_INDEX]);
            break;
        }

        port = atoi(args[PORT_INDEX]);

        server_struct.sin_family = AF_INET;
        server_struct.sin_addr.s_addr = inet_addr(args[ADDR_INDEX]);
        server_struct.sin_port = htons(port);

        g_server_sock = socket(PF_INET, (SOCK_STREAM | SOCK_NONBLOCK), IPPROTO_TCP);

        if(-1 == g_server_sock)
        {
            printf("Error at socket(): %s\n", strerror(errno));
            break;
        }

        ret_val = setsockopt(g_server_sock, SOL_SOCKET, SO_REUSEADDR, &read_opt, sizeof(read_opt));

        if(-1 == ret_val)
        {
            printf("Error at setsockopt(): %s\n", strerror(errno));
            break;
        }

        ret_val = bind(g_server_sock, (struct sockaddr *) &server_struct, sizeof(struct sockaddr));

        if(-1 == ret_val)
        {
            printf("Error at bind(): %s\n", strerror(errno));
            break;
        }

        ret_val = listen(g_server_sock, MAX_NUM_OF_CLIENTS);

        if(-1 == ret_val)
        {
            printf("Error at listen(): %s\n", strerror(errno));
            break;
        }

        ret_val = register_to_signals();

        if(-1 == ret_val)
        {
            printf("Error at register_to_signals()\n");
            break;
        }

        ret_val = disable_signals();

        if(-1 == ret_val)
        {
            printf("Error at disable_signals()\n");
            break;
        }

        ret_val = init_server_tls();

        if(-1 == ret_val)
        {
            printf("Error at init_server_tls()\n");
            break;
        }

        g_server_status = RUNNING;

        ret_val = 0;
    } while(false);

    if((-1 == ret_val) && (-1 != g_server_sock))
    {
        ret_val = deinit_server();

        if(-1 == ret_val)
        {
            printf("Error at deinit_server()\n");
        }

        ret_val = -1;
    }

    return ret_val;
}

/**
 * @brief  Run server entity
 */
extern void run_server(void)
{
    int ret_val = -1;
    int client_sock = -1;
    fd_set read_fds = {0};
    struct timeval timeout = {0};

    if(-1 == g_server_sock)
    {
        printf("Invalid data: g_server_sock");
    }
    else
    {
        while(RUNNING == g_server_status)
        {
            FD_ZERO(&read_fds);
            FD_SET(g_server_sock, &read_fds);

            timeout.tv_sec = SELECT_TIMEOUT_SEC;
            timeout.tv_usec = 0;

            ret_val = select((g_server_sock + 1), &read_fds, NULL, NULL, &timeout);

            if(-1 == ret_val)
            {
                printf("Error at select(): %s\n", strerror(errno));
            }
            else if(0 < ret_val)
            {
                if(true == FD_ISSET(g_server_sock, &read_fds))
                {
                    client_sock = accept(g_server_sock, NULL, NULL);

                    if(-1 == client_sock)
                    {
                        printf("Error at accept(): %s\n", strerror(errno));
                    }
                    else
                    {
                        ret_val = init_client(client_sock);

                        if(-1 == ret_val)
                        {
                            printf("Error at init_client()\n");
                        }
                    }
                }
            }
        }
    }
}

/**
 * @brief  De-initialize server entity
 *
 * @return 0 on success, -1 on failure
 */
extern int deinit_server(void)
{
    int ret_val = -1;

    if(-1 == g_server_sock)
    {
        printf("Invalid data: g_server_sock");
    }
    else
    {
        g_server_status = STOPPED;

        ret_val = close(g_server_sock);

        if(-1 == ret_val)
        {
            printf("Error at close(): %s\n", strerror(errno));
        }
        else
        {
            g_server_sock = -1;
        }

        ret_val = deinit_server_tls();

        if(-1 == ret_val)
        {
            printf("Error at deinit_server_tls()\n");
        }
    }

    return ret_val;
}

/**********************************************************************************
 * LOCAL FUNCTION DEFINITIONS
**********************************************************************************/

/**
 * @brief  Register Server entity to UNIX signals
 *
 * @return 0 on success, -1 on failure
 */
static int register_to_signals(void)
{
    int ret_val = -1;

    if(SIG_ERR == signal(SIGINT, signal_handler_cb))
    {
        printf("Error at signal(SIGNINT): %s\n", strerror(errno));
    }
    else
    {
        ret_val = 0;
    }

    return ret_val;
}

/**
 * @brief     UNIX signals callback handler
 *
 * @param[in] signal - Expected UNIX signal
 */
static void signal_handler_cb(const int signal)
{
    printf("\nReceived signal: %d\n", signal);

    switch(signal)
    {
        case SIGINT:
        {
            g_server_status = STOPPED;
            break;
        }
        default:
        {
            break;
        }
    }
}

/**
 * @brief  Disable specific signals for Server entity
 *
 * @return 0 on success, -1 on failure
 */
static int disable_signals(void)
{
    int ret_val = -1;

    if(SIG_ERR == signal(SIGPIPE, SIG_IGN))
    {
        printf("Error at signal(SIGPIPE): %s\n", strerror(errno));
    }
    else
    {
        ret_val = 0;
    }

    return ret_val;
}

/**
 * @brief     Create thread to handle client requests
 *
 * @param[in] client_sock - Client socket
 *
 * @return    0 on success, -1 on failure
 */
static int init_client(const int client_sock)
{
    int ret_val = -1;
    pthread_t client_handler_th_id = -1;

    ret_val = pthread_create(&client_handler_th_id, NULL, &client_handler_thread_func, &client_sock);

    if(0 != ret_val)
    {
        printf("Error at pthread_create(): %s\n", strerror(ret_val));

        ret_val = deinit_client(client_sock);

        if(-1 == ret_val)
        {
            printf("Error at deinit_client()\n");
        }

        ret_val = -1;
    }
    else
    {
        ret_val = pthread_detach(client_handler_th_id);

        if(0 != ret_val)
        {
            printf("Error at pthread_detach(): %s\n", strerror(ret_val));
            ret_val = -1;
        }
        else
        {
            ret_val = 0;
        }
    }

    return ret_val;
}

/**
 * @brief     Close client communication socket
 *
 * @param[in] client_sock - Client socket
 *
 * @return    0 on success, -1 on failure
 */
static int deinit_client(const int client_sock)
{
    int ret_val = -1;

    ret_val = close(client_sock);

    if(-1 == ret_val)
    {
        printf("Error at close(): %s\n", strerror(errno));
    }

    return ret_val;
}

/**
 * @brief     Thread which handle client requests
 *
 * @param[in] arg - Client socket
 *
 * @return    NULL
 */
static void *client_handler_thread_func(const void *arg)
{
    int client_sock = *((int *) arg);
    int ret_val = -1;
    int client_status = STOPPED;
    fd_set read_fds = {0};
    struct timeval timeout = {0};
    SSL *client_ssl_struct = NULL;

    ret_val = perform_tls_handshake(client_sock, &client_ssl_struct);

    if(-1 != ret_val)
    {
        client_status = RUNNING;
    }

    while((RUNNING == client_status) && (RUNNING == g_server_status))
    {
        FD_ZERO(&read_fds);
        FD_SET(client_sock, &read_fds);

        timeout.tv_sec = SELECT_TIMEOUT_SEC;
        timeout.tv_usec = 0;

        ret_val = select((client_sock + 1), &read_fds, NULL, NULL, &timeout);

        if(-1 == ret_val)
        {
            printf("Error at select(): %s\n", strerror(errno));
        }
        else if(0 < ret_val)
        {
            if(true == FD_ISSET(client_sock, &read_fds))
            {
                /* Handle client request */
            }
        }
    }

    ret_val = deinit_client(client_sock);

    if(-1 == ret_val)
    {
        printf("Error at deinit_client()\n");
    }

    if(NULL != client_ssl_struct)
    {
        SSL_free(client_ssl_struct);
    }

    return NULL;
}

/**
 * @brief  Initialize TLS for server entity
 *
 * @return 0 on success, -1 on failure
 */
static int init_server_tls(void)
{
    int ret_val = -1;
    SSL_METHOD *server_ssl_method = NULL;

    do
    {
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();

        server_ssl_method = TLSv1_2_server_method();

        if(NULL == server_ssl_method)
        {
            printf("Error at TLSv1_2_server_method()\n");
            ERR_print_errors_fp(stderr);
            break;
        }

        g_server_ssl_ctx = SSL_CTX_new(server_ssl_method);

        if(NULL == g_server_ssl_ctx)
        {
            printf("Error at SSL_CTX_new()\n");
            ERR_print_errors_fp(stderr);
            break;
        }

        ret_val = load_server_certificates();

        if(-1 == ret_val)
        {
            printf("Error at load_server_certificates()\n");
            break;
        }

        ret_val = 0;
    } while(false);

    return ret_val;
}

/**
 * @brief  De-initialize TLS for server entity
 *
 * @return 0 on success, -1 on failure
 */
static int deinit_server_tls(void)
{
    int ret_val = 0;

    if(NULL != g_server_ssl_ctx)
    {
        SSL_CTX_free(g_server_ssl_ctx);
    }

    return ret_val;
}

/**
 * @brief  Load Server certificate files
 *
 * @return 0 on success, -1 on failure
 */
static int load_server_certificates(void)
{
    int ret_val = -1;
    const char *SERVER_CERT_FILE_PATH = "../cert/server_cert.pem";

    do
    {
        ret_val = SSL_CTX_use_certificate_file(g_server_ssl_ctx, SERVER_CERT_FILE_PATH, SSL_FILETYPE_PEM);

        if(1 != ret_val)
        {
            printf("Error at SSL_CTX_use_certificate_file()\n");
            ERR_print_errors_fp(stderr);
            ret_val = -1;
            break;
        }

        ret_val = SSL_CTX_use_PrivateKey_file(g_server_ssl_ctx, SERVER_CERT_FILE_PATH, SSL_FILETYPE_PEM);

        if(1 != ret_val)
        {
            printf("Error at SSL_CTX_use_PrivateKey_file()\n");
            ERR_print_errors_fp(stderr);
            ret_val = -1;
            break;
        }

        ret_val = SSL_CTX_check_private_key(g_server_ssl_ctx);

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

/**
 * @brief      Perform TLS Handshake with Client entity
 *
 * @param[in]  client_sock - Client Socket
 * @param[out] client_ssl_struct - Client SSL Structure
 *
 * @return     0 on success, -1 on failure
 */
static int perform_tls_handshake(const int client_sock, SSL **client_ssl_struct)
{
    int ret_val = -1;
    SSL *temp_client_ssl_struct = NULL;

    do
    {
        temp_client_ssl_struct = SSL_new(g_server_ssl_ctx);

        if(NULL == temp_client_ssl_struct)
        {
            printf("Error at SSL_new()\n");
            ERR_print_errors_fp(stderr);
            break;
        }

        ret_val = SSL_set_fd(temp_client_ssl_struct, client_sock);

        if(1 != ret_val)
        {
            printf("Error at SSL_set_fd()\n");
            ERR_print_errors_fp(stderr);
            break;
        }

        ret_val = SSL_accept(temp_client_ssl_struct);

        if(1 != ret_val)
        {
            printf("Error at SSL_accept()\n");
            ERR_print_errors_fp(stderr);
            break;
        }

        *client_ssl_struct = SSL_dup(temp_client_ssl_struct);
    } while(false);

    if(NULL != temp_client_ssl_struct)
    {
        SSL_free(temp_client_ssl_struct);
    }

    return ret_val;
}
