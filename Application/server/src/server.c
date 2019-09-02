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
#include <openssl/ssl.h>

/**********************************************************************************
 * INTERFACES
**********************************************************************************/

#include "server.h"
#include "server_tls.h"

/**********************************************************************************
 * LOCAL DEFINES
**********************************************************************************/

#define RUNNING 1
#define STOPPED 0
#define SELECT_TIMEOUT_SEC 5

/**********************************************************************************
 * LOCAL GLOBAL VARIABLES
**********************************************************************************/

static int g_server_sock = -1;
static SSL_CTX *g_server_tls_ctx = NULL;
static int g_server_status = STOPPED;
static pthread_mutex_t g_server_status_lock = PTHREAD_MUTEX_INITIALIZER;

/**********************************************************************************
 * LOCAL FUNCTION DECLARATIONS
**********************************************************************************/

static int      register_to_signals       (void);
static void     signal_handler_cb         (const int signal);
static int      disable_signals           (void);
static int      init_client               (const int client_sock);
static int      deinit_client             (const int client_sock);
static void    *client_handler_thread_func(const void *arg);
static void     set_server_status         (const int server_status);
static int      get_server_status         (void);

/**********************************************************************************
 * GLOBAL FUNCTION DEFINITIONS
**********************************************************************************/

/**
 * @fn     init_server
 *
 * @brief  Initialize server entity
 *
 * @return  0 on success, -1 on failure
 */
extern int init_server(const int num_of_args, const char *args[])
{
    int ret_val = -1;
    int port = -1;
    int read_opt = 1;
    struct sockaddr_in server_struct = {0};
    const int MAX_NUM_OF_CLIENTS = 100;
    const int NUM_OF_CMD_LINE_ARGS = 3;
    const int EXEC_INDEX = 0;
    const int ADDR_INDEX = 1;
    const int PORT_INDEX = 2;

    if(-1 != g_server_sock)
    {
        printf("Invalid data: g_client_sock\n");
    }
    else
    {
        do
        {
            if(NUM_OF_CMD_LINE_ARGS != num_of_args)
            {
                printf("Invalid command line arguments. Proper syntax: %s <SERVER_ADRESS> <SERVER_PORT>\n", args[EXEC_INDEX]);
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

            ret_val = init_server_tls(g_server_tls_ctx);

            if( (-1 == ret_val) && (NULL == g_server_tls_ctx) )
            {
                printf("Error at init_server_tls()\n");
                break;
            }

            set_server_status(RUNNING);

            ret_val = 0;
        } while(false);

        if((-1 == ret_val) && (-1 != g_server_sock))
        {
            ret_val = deinit_server();

            if(-1 == ret_val)
            {
                printf("Error at deinit_server()\n");
            }

            ret_val = deinit_server_tls(&g_server_tls_ctx);

            if(-1 == ret_val)
            {
                printf("Error at deinit_server_tls()\n");
            }

            ret_val = -1; 
        }
    }

    return ret_val;
}

/**
 * @fn     run_server
 *
 * @brief  Run server entity
 *
 * @return 0 on success, -1 on failure
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
        while(RUNNING == get_server_status())
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
 * @fn     deinit_server
 *
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
        set_server_status(STOPPED);

        ret_val = close(g_server_sock);

        if(-1 == ret_val)
        {
            printf("Error at close(): %s\n", strerror(errno));
        }

        g_server_sock = -1;

        ret_val = deinit_server_tls(g_server_tls_ctx);

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

static void signal_handler_cb(const int signal)
{
    printf("\nReceived signal: %d\n", signal);

    switch(signal)
    {
        case SIGINT:
        {
            set_server_status(STOPPED);
            break;
        }
        default:
        {
            break;
        }
    }
}

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

static int init_client(const int client_sock)
{
    int ret_val = -1;
    pthread_t client_handler_th_id = -1;

    ret_val = pthread_create(&client_handler_th_id, NULL, (void *) &client_handler_thread_func, (void *) &client_sock);

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

static void *client_handler_thread_func(const void *arg)
{
    int client_sock = *((int *) arg);
    int ret_val = -1;
    int client_status = STOPPED;
    fd_set read_fds = {0};
    struct timeval timeout = {0};
    SSL *client_handler_tls = NULL;

    do
    {
        client_handler_tls = SSL_new(g_server_tls_ctx);

        if(NULL == client_handler_tls)
        {
            printf("Error at SSL_new()\n");
            ERR_print_errors_fp(stderr);
            break;
        }

        ret_val = SSL_set_fd(client_handler_tls, client_sock);

        if(1 != ret_val)
        {
            printf("Error at SSL_set_fd()\n");
            ERR_print_errors_fp(stderr);
            break;
        }

        ret_val = SSL_accept(client_handler_tls);

        if(1 != ret_val)
        {
            printf("Error at SSL_accept()\n");
            ERR_print_errors_fp(stderr);
            break;
        }

        client_status = RUNNING;
    } while(false);

    while((RUNNING == client_status) && (RUNNING == get_server_status()))
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

    if(NULL != client_handler_tls)
    {
        SSL_free(client_handler_tls);
    }

    return NULL;
}

static void set_server_status(const int server_status)
{
    pthread_mutex_lock(&g_server_status_lock);
    g_server_status = server_status;
    pthread_mutex_unlock(&g_server_status_lock);
}

static int get_server_status(void)
{
    int server_status = STOPPED;

    pthread_mutex_lock(&g_server_status_lock);
    server_status = g_server_status;
    pthread_mutex_unlock(&g_server_status_lock);

    return server_status;
}
