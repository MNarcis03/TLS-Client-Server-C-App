#ifndef CLIENT_H
#define CLIENT_H

/**********************************************************************************
 * CLIENT INTERFACE
**********************************************************************************/

/**
 * @brief     Initialize client entity
 *
 * @param[in] num_of_args - Number of Command Line Arguments
 * @param[in] args - Arguments Array
 *
 * @return    0 on success, -1 on failure
 */
extern int init_client(const int num_of_args, const char *args[]);

/**
 * @brief  Run server entity
 *
 * @return 0 on success, -1 on failure
 */
extern void run_client(void);

/**
 * @brief  De-initialize client entity
 *
 * @return 0 on success, -1 on failure
 */
extern int deinit_client(void);

#endif /* CLIENT_H */