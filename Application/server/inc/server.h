#ifndef SERVER_H
#define SERVER_H

/**********************************************************************************
 * SERVER INTERFACE
**********************************************************************************/

/**
 * @fn     start_server
 *
 * @brief  Initialize server entity
 *
 * @return  0 on success, -1 on failure
 */
extern int init_server(const int num_of_args, const char *args[]);

/**
 * @fn     run_server
 * 
 * @brief  Run server entity
 * 
 * @return 0 on success, -1 on failure
 */
extern void run_server(void);

/**
 * @fn     deinit_server
 * 
 * @brief  De-initialize server entity
 * 
 * @return 0 on success, -1 on failure
 */
extern int deinit_server(void);

#endif /* SERVER_H */