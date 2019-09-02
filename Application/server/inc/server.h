#ifndef SERVER_H
#define SERVER_H

/**********************************************************************************
 * SERVER INTERFACE
**********************************************************************************/

/**
 * @brief     Initialize server entity
 *
 * @param[in] num_of_args - Number of Command Line Arguments
 * @param[in] args - Arguments Array
 *
 * @return    0 on success, -1 on failure
 */
extern int init_server(const int num_of_args, const char *args[]);

/**
 * @brief  Run server entity
 *
 * @return 0 on success, -1 on failure
 */
extern void run_server(void);

/**
 * @brief  De-initialize server entity
 *
 * @return 0 on success, -1 on failure
 */
extern int deinit_server(void);

#endif /* SERVER_H */