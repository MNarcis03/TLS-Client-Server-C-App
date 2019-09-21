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

#include "client.h"

/**********************************************************************************
 * LOCAL DEFINES
**********************************************************************************/

#define RUNNING 1
#define STOPPED 0

/**********************************************************************************
 * LOCAL GLOBAL VARIABLES
**********************************************************************************/

static int      g_client_sock    = -1;
static int      g_client_status  = STOPPED;
static SSL_CTX *g_client_ssl_ctx = NULL;

/**********************************************************************************
 * LOCAL FUNCTION DECLARATIONS
**********************************************************************************/

static int  register_to_signals  (void);
static int  disable_signals      (void);
static void signal_handler_cb    (const int signal);
static int  init_client_tls      (void);
static int  deinit_client_tls    (void);
static int  perform_tls_handshake(SSL **client_ssl_struct);

/**********************************************************************************
 * GLOBAL FUNCTION DEFINITIONS
**********************************************************************************/

/**
 * @brief     Initialize client entity
 *
 * @param[in] num_of_args - Number of Command Line Arguments
 * @param[in] args - Arguments Array
 *
 * @return    0 on success, -1 on failure
 */
extern int init_client(const int num_of_args, const char *args[])
{
    int ret_val = -1;
    int port = -1;
    int read_opt = 1;
    struct sockaddr_in server_struct = {0};
    const int NUM_OF_CMD_LINE_ARGS = 3;
    const int EXEC_INDEX = 0;
    const int ADDR_INDEX = 1;
    const int PORT_INDEX = 2;

    do
    {
        if(-1 != g_client_sock)
        {
            printf("Invalid data: g_client_sock\n");
            break;
        }

        if(NUM_OF_CMD_LINE_ARGS != num_of_args)
        {
            printf("Invalid command line arguments. Proper syntax: %s <SERVER_ADRESS> <SERVER_PORT>\n", args[EXEC_INDEX]);
            break;
        }

        port = atoi(args[PORT_INDEX]);

        server_struct.sin_family = AF_INET;
        server_struct.sin_addr.s_addr = inet_addr(args[ADDR_INDEX]);
        server_struct.sin_port = htons(port);

        g_client_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

        if(-1 == g_client_sock)
        {
            printf("Error at socket(): %s\n", strerror(errno));
            break;
        }

        ret_val = setsockopt(g_client_sock, SOL_SOCKET, SO_REUSEADDR, &read_opt, sizeof(read_opt));

        if(-1 == ret_val)
        {
            printf("Error at setsockopt(): %s\n", strerror(errno));
            break;
        }

        ret_val = connect(g_client_sock, (struct sockaddr *) &server_struct, sizeof(struct sockaddr));

        if(-1 == ret_val)
        {
            printf("Error at connect(): %s\n", strerror(errno));
            break;
        }

        ret_val = init_client_tls();

        if(-1 == ret_val)
        {
            printf("Error at init_client_tls()\n");
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

        ret_val = 0;
    } while(false);

    if((-1 == ret_val) && (-1 != g_client_sock))
    {
        ret_val = deinit_client();

        if(-1 == ret_val)
        {
            printf("Error at deinit_client()\n");
        }

        ret_val = -1;
    }

    return ret_val;
}

/**
 * @brief  Run client entity
 *
 * @return 0 on success, -1 on failure
 */
extern void run_client(void)
{
    int ret_val = -1;
    SSL *client_ssl_struct = NULL;
    const int RECV_STR_CAPACITY = 256;
    char recv_str[RECV_STR_CAPACITY];

    if(-1 == g_client_sock)
    {
        printf("Invalid data: g_client_sock\n");
    }
    else
    {
        ret_val = perform_tls_handshake(&client_ssl_struct);

        if(-1 != ret_val)
        {
            g_client_status = RUNNING;
        }

        while(RUNNING == g_client_status)
        {
            ret_val = SSL_write(client_ssl_struct, "Client Hello", sizeof("Client Hello"));

            if(0 < ret_val)
            {
                memset(recv_str, 0, RECV_STR_CAPACITY);

                ret_val = SSL_read(client_ssl_struct, recv_str, RECV_STR_CAPACITY);

                if(0 >= ret_val)
                {
                    printf("Error when recv from server: %d\n", ret_val);
                    g_client_status = STOPPED;
                }
                else
                {
                    printf("Recv from server: %s\n", recv_str);
                }
            }
            else if(0 >= ret_val)
            {
                printf("Error when send to server: %d\n", ret_val);
                g_client_status = STOPPED;
            }

            sleep(1);
        }

        if(NULL != client_ssl_struct)
        {
            SSL_shutdown(client_ssl_struct);
            SSL_free(client_ssl_struct);
        }
    }
}

/**
 * @brief  De-initialize client entity
 *
 * @return 0 on success, -1 on failure
 */
extern int deinit_client(void)
{
    int ret_val = -1;

    if(-1 == g_client_sock)
    {
        printf("Invalid data: g_client_sock\n");
    }
    else
    {
        g_client_status = STOPPED;

        ret_val = close(g_client_sock);

        if(-1 == ret_val)
        {
            printf("Error at close(): %s\n", strerror(errno));
        }

        ret_val = deinit_client_tls();

        if(-1 == ret_val)
        {
            printf("Error at deinit_server_tls()\n");
        }

        g_client_sock = -1;
    }

    return ret_val;
}

/**********************************************************************************
 * LOCAL FUNCTION DEFINITIONS
**********************************************************************************/

/**
 * @brief  Register to UNIX signals
 *
 * @return 0 on success, -1 on failure
 */
int register_to_signals(void)
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
            g_client_status = STOPPED;
            break;
        }
        default:
        {
            break;
        }
    }
}

/**
 * @brief  Initialize TLS for client entity
 *
 * @return 0 on success, -1 on failure
 */
static int init_client_tls(void)
{
    int ret_val = -1;
    SSL_METHOD *client_ssl_method = NULL;

    do
    {
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();

        client_ssl_method = TLSv1_2_client_method();

        if(NULL == client_ssl_method)
        {
            printf("Error at TLSv1_2_client_method()\n");
            ERR_print_errors_fp(stderr);
            break;
        }

        g_client_ssl_ctx = SSL_CTX_new(client_ssl_method);

        if(NULL == g_client_ssl_ctx)
        {
            printf("Error at SSL_CTX_new()\n");
            ERR_print_errors_fp(stderr);
            break;
        }

        ret_val = 0;
    } while(false);

    return ret_val;
}

/**
 * @brief  De-initialize TLS for client entity
 *
 * @return 0 on success, -1 on failure
 */
static int deinit_client_tls(void)
{
    int ret_val = 0;

    if(NULL != g_client_ssl_ctx)
    {
        SSL_CTX_free(g_client_ssl_ctx);
    }

    return ret_val;
}

/**
 * @brief      Perform TLS Handshake with Server entity
 *
 * @param[out] client_ssl_struct - Client SSL Structure
 *
 * @return     0 on success, -1 on failure
 */
static int perform_tls_handshake(SSL **client_ssl_struct)
{
    int ret_val = -1;
    SSL *temp_client_ssl_struct = NULL;

    do
    {
        temp_client_ssl_struct = SSL_new(g_client_ssl_ctx);

        if(NULL == temp_client_ssl_struct)
        {
            printf("Error at SSL_new()\n");
            ERR_print_errors_fp(stderr);
            break;
        }

        ret_val = SSL_set_fd(temp_client_ssl_struct, g_client_sock);

        if(1 != ret_val)
        {
            printf("Error at SSL_set_fd()\n");
            ERR_print_errors_fp(stderr);
            break;
        }

        ret_val = SSL_connect(temp_client_ssl_struct);

        if(1 != ret_val)
        {
            printf("Error at SSL_connect()\n");
            ERR_print_errors_fp(stderr);
            break;
        }

        ret_val = SSL_do_handshake(temp_client_ssl_struct);

        if(1 != ret_val)
        {
            printf("Error at SSL_do_handshake()\n");
            ERR_print_errors_fp(stderr);
            break;
        }

        *client_ssl_struct = SSL_dup(temp_client_ssl_struct);

        ret_val = 0;
    } while(false);

    if(NULL != temp_client_ssl_struct)
    {
        SSL_free(temp_client_ssl_struct);
    }

    return ret_val;
}
