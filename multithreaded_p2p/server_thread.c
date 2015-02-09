//
//  server_thread.c
//  multithreaded_p2p
//
//  Created by Jorge on 2/2/15.
//  Copyright (c) 2015 UCLA. All rights reserved.
//

#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>

#include "server_thread.h"
#include "errors.h"


struct client_handle_args
{
  int sock;  /* socket descriptor */
};

void *server_thread(void *args)
{
  int server, client;                    /* socket descriptors */
  struct sockaddr_in servAddr;           /* this server address */
  struct sockaddr_in clntAddr;           /* remote client address */
  unsigned int clntLen;                  /* client address length */
  struct server_args *servArgs;          /* server thread arguments */
  struct client_handle_args *clntArgs;   /* client handle thread arguments */
  pthread_t thread;                      /* client thread */
  int status;                            /* for pthread returns */
  
  /* Get the server arguments */
  if(args == NULL)
  {
    fprintf(stderr, "Server: invalid arguments\n");
    exit(EXIT_FAILURE);
  }
  servArgs = (struct server_args*)args;
  
  /* Create socket for incoming connections */
  server = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  if(server < 0)
    err_message("socket() failed");
  
  /* Construct local address structure */
  memset(&servAddr, 0x00, sizeof(servAddr));         /* clear the struct */
  servAddr.sin_family      = AF_INET;                /* Internet addr family */
  servAddr.sin_addr.s_addr = htonl(INADDR_ANY);      /* any incoming iface */
  servAddr.sin_port        = htons(servArgs->port);  /* local port */
  
  /* Bind to the local address */
  if(bind(server, (struct sockaddr *) &servAddr, sizeof(servAddr)) < 0)
    err_message("bind() failed");

  /* Mark the socket so it will listen for incoming connections */
  if(listen(server, servArgs->max_pending) < 0)
    err_message("listen() failed");
  
  /* Messaging the terminal for accepting connections */
  printf("Server accepting connections on port %lu...\n", servArgs->port);
  
  /* Handle the incoming connections */
  for(;;)
  {
    /* Set the size of the in-out parameter */
    clntLen = sizeof(clntAddr);
    
    /* Wait for a client to connect */
    client = accept(server, (struct sockaddr *) &clntAddr, &clntLen);
    if(client < 0)
      err_message("accept() failed");
    
    /* spawn a client handle thread to server the request */
    clntArgs = (struct client_handle_args *)malloc(sizeof(struct client_handle_args));
    clntArgs->sock = client;
    status = pthread_create(&thread, NULL, client_handle, clntArgs);
    if(status != 0)
      err_abort(status, "Create client thread");
  }
  
  free(servArgs);
  
  return NULL;
}

void *client_handle(void *args)
{
  char buf[MAX_BUF_LEN];                  /* input buffer */
  int recvMsgSize;                        /* size of received message */
  struct sockaddr_in clntAddr;            /* remote client address */
  socklen_t clntLen;                      /* client address length */
  struct client_handle_args *clntArgs;    /* client handle thread arguments */
  int status;                             /* for pthread returns */
  
  /* Detach this thread from the main thread */
  status = pthread_detach(pthread_self());
  if(status != 0)
    err_abort(status, "Detach thread");
  
  /* Map the argument to the the local pointer */
  if(args == NULL)
    err_message("Client args");
  clntArgs = (struct client_handle_args *)args;
  
  /* Get remote client name */
  clntLen = sizeof(clntAddr);
  if(getpeername(clntArgs->sock, (struct sockaddr *)&clntAddr, &clntLen) < 0)
    err_message("getsockname() failed");
  printf("[%s:%u]: ", inet_ntoa(clntAddr.sin_addr), ntohs(clntAddr.sin_port));

  /* Receive message from client */
  if((recvMsgSize=recv(clntArgs->sock, buf, MAX_BUF_LEN-1, 0)) < 0)
    err_message("recv() failed");
  buf[recvMsgSize] = 0;         /* terminate the c-string */
  printf("%s", buf);            /* print the buffer */
  
  /* Send received data and receive again until end of transmission */
  while(recvMsgSize > 0)  /* zero indicates end of transmission */
  {
    /* Echo message back to client */
    if(send(clntArgs->sock, buf, recvMsgSize, 0) != recvMsgSize)
      err_message("send() failed");
    
    /* See if there is more data to receive */
    if((recvMsgSize=recv(clntArgs->sock, buf, MAX_BUF_LEN-1, 0)) < 0)
      err_message("recv() failed");
    buf[recvMsgSize] = 0;         /* terminate the c-string */
    printf("%s", buf);            /* print the buffer */
  }
  printf("\n");  /* final line feed */
  
  free(clntArgs);
  close(clntArgs->sock);
  
  return NULL;
}
