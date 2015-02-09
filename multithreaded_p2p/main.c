//
//  main.c
//  multithreaded_p2p
//
//  Created by Jorge on 2/2/15.
//  Copyright (c) 2015 UCLA. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#include "resources.h"
#include "server_thread.h"
#include "client_thread.h"
#include "errors.h"

void print_help();

int main(int argc, char *argv[])
{
  char line[MAX_STR_LEN];        /* command line */
  char *p;                       /* char pointer to search within line */
  int port;                      /* server port */
  int status;                    /* for pthread returns */
  pthread_t server, client;      /* server and client threads */
  struct server_args *servArgs;  /* server thread arguments */
  struct client_args *clntArgs;  /* client thread arguments */
  
  /* parameter testing */
  if(argc != 2)
  {
    fprintf(stderr, "Usage: %s <port>\n", argv[0]);
    exit(EXIT_FAILURE);
  }
  port = atoi(argv[1]);
  if(port < 1024)
  {
    fprintf(stderr, "Invalid port number");
    exit(EXIT_FAILURE);
  }
  
  /* Start the server thread */
  servArgs = (struct server_args *)malloc(sizeof(struct server_args));
  servArgs->port = port;
  servArgs->max_pending = 5;
  status = pthread_create(&server, NULL, server_thread, servArgs);
  if(status != 0)
    err_abort(status, "Server thread");
  sleep(1);
  
  /* Begin taking commands for the clients requests here */
  print_help();
  while(1)
  {
    printf("p2p> ");
    if(fgets(line, sizeof(line), stdin) == NULL)
      exit(0);
    if((p=strchr(line,'\n')) != NULL)
      *p = '\0';
    
    if(strlen(line) < 1)
      continue;
    if(strcmp(line, "exit") == 0)
      break;
    if(strcmp(line, "help") == 0)
    {
      print_help();
      continue;
    }
    
    /*
     * Initiate a client transmission of data
     */
    if((p=strstr(line, "send")) != NULL && p == line)
    {
      /* get client thread arguments */
      clntArgs = (struct client_args *)malloc(sizeof(struct client_args));
      if(sscanf(line+4, "%127s %lu",
                clntArgs->hostname, &clntArgs->port) != 2)
      {
        fprintf(stderr, "Bad command\n");
        free(clntArgs);
        continue;
      }
      
      /* prompt for data to transmit */
      printf("enter message> ");
      if(fgets(clntArgs->msg, sizeof(clntArgs->msg), stdin) == NULL)
      {
        fprintf(stderr, "Bad command\n");
        free(clntArgs);
        continue;
      }
      if((p=strchr(clntArgs->msg,'\n')) != NULL)
        *p = '\0';

      /* spawn new client thread */
      status = pthread_create(&client, NULL, client_thread, clntArgs);
      if(status != 0)
        err_abort(status, "Client thread");
    }
  }
  
  
  return 0;
}

void print_help()
{
  printf("List of commands:\n");
  printf(" send <IP or hostname> <port>\n");
  printf(" exit\n");
  printf(" help\n");
}
