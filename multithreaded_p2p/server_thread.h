//
//  server_thread.h
//  multithreaded_p2p
//
//  Created by Jorge on 2/2/15.
//  Copyright (c) 2015 UCLA. All rights reserved.
//

#ifndef _SERVER_THREAD_H_
#define _SERVER_THREAD_H_

#include "resources.h"


struct server_args
{
  size_t port;         /* port number */
  size_t max_pending;  /* maximum simultaneous connections */
};

void *server_thread(void *args);
void *client_handle(void *args);

#endif /* _SERVER_THREAD_H_ */
