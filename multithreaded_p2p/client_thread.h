//
//  client_thread.h
//  multithreaded_p2p
//
//  Created by Jorge on 2/3/15.
//  Copyright (c) 2015 UCLA. All rights reserved.
//

#ifndef _CLIENT_THREAD_H_
#define _CLIENT_THREAD_H_

#include "resources.h"


struct client_args
{
  size_t port;               /* remote server port */
  char hostname[MAX_STR_LEN];      /* hostname of server */
  char msg[MAX_STR_LEN];           /* data to transfer */
};

void *client_thread(void *args);

#endif /* _CLIENT_THREAD_H_ */
