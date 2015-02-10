//
//  resources.h
//  multithreaded_p2p
//
//  Created by Jorge on 2/3/15.
//  Copyright (c) 2015 UCLA. All rights reserved.
//

#ifndef _RESOURCES_H_
#define _RESOURCES_H_

#include <pthread.h>

#define MAX_BUF_LEN 32    /* max buffer size */
#define MAX_STR_LEN 128   /* max string size */

struct buffer
{
  char data[32];
  size_t size;
  int b, e;
};

#endif /* _RESOURCES_H_ */
