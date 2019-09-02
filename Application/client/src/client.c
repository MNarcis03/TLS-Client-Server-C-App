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

/**********************************************************************************
 * INTERFACES
**********************************************************************************/

#include "client.h"
#include "tls.h"

/**********************************************************************************
 * LOCAL DEFINES
**********************************************************************************/

#define RUNNING 1
#define STOPPED 0

/**********************************************************************************
 * LOCAL GLOBAL VARIABLES
**********************************************************************************/

static int g_client_sock = -1;
static int g_client_status = STOPPED;

/**********************************************************************************
 * LOCAL FUNCTION DECLARATIONS
**********************************************************************************/

static int register_to_signals(void);

static void signal_handler_cb(const int signal);

/**********************************************************************************
 * GLOBAL FUNCTION DEFINITIONS
**********************************************************************************/

/**
 * @fn     init_client
 *
 * @brief  Initialize client entity
 *
 * @return  0 on success, -1 on failure
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

    if(-1 != g_client_sock)
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

            ret_val = register_to_signals();

            if(-1 == ret_val)
            {
                printf("Error at register_to_signals()\n");
                break;
            }

            g_client_status = RUNNING;

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
    }

    return ret_val;
}

/**
 * @fn     run_client
 *
 * @brief  Run client entity
 *
 * @return 0 on success, -1 on failure
 */
extern void run_client(void)
{
    int ret_val = -1;
    fd_set read_fds = {0};
    struct timeval timeout = {0};
    const int SELECT_TIMEOUT_SEC = 5;

    if(-1 == g_client_sock)
    {
        printf("Invalid data: g_client_sock\n");
    }
    else
    {
        /* Negotiate */

        while(RUNNING == g_client_status)
        {
            FD_ZERO(&read_fds);
            FD_SET(g_client_sock, &read_fds);

            timeout.tv_sec = SELECT_TIMEOUT_SEC;
            timeout.tv_usec = 0;

            ret_val = select((g_client_sock + 1), &read_fds, NULL, NULL, &timeout);

            if(-1 == ret_val)
            {
                printf("Error at select(): %s\n", strerror(errno));
            }
            else if(0 < ret_val)
            {
                if(true == FD_ISSET(g_client_sock, &read_fds))
                {
                    /* Create request */
                }
            }
        }
    }
}

/**
 * @fn     deinit_client
 *
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

        g_client_sock = -1;
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
            g_client_status = STOPPED;
            break;
        }
        default:
        {
            break;
        }
    }
}
