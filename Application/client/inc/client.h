#ifndef CLIENT_H
#define CLIENT_H

/**********************************************************************************
 * CLIENT INTERFACE
**********************************************************************************/

/**
 * @fn     start_client
 *
 * @brief  Initialize client entity
 *
 * @return  0 on success, -1 on failure
 */
extern int init_client(const int num_of_args, const char *args[]);

/**
 * @fn     run_client
 * 
 * @brief  Run server entity
 * 
 * @return 0 on success, -1 on failure
 */
extern void run_client(void);

/**
 * @fn     deinit_client
 * 
 * @brief  De-initialize client entity
 * 
 * @return 0 on success, -1 on failure
 */
extern int deinit_client(void);

#endif /* CLIENT_H */