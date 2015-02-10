//
//  client_thread.c
//  multithreaded_p2p
//
//  Created by Jorge on 2/3/15.
//  Copyright (c) 2015 UCLA. All rights reserved.
//

#include <stdio.h>       /* for printf(), fprintf() */
#include <sys/socket.h>  /* for socket(), connect(), send(), recv() */
#include <arpa/inet.h>   /* for sockaddr_in and inet_addr() */
#include <stdlib.h>      /* for atoi() */
#include <string.h>      /* for memset() */
#include <unistd.h>      /* for close() */
#include <netdb.h>       /* for gethostbyname() */
#include <pthread.h>     /* for pthread_create() */

#include "client_thread.h"
#include "errors.h"

void *client_thread(void *args)
{
  int sock;                     /* socket descriptor */
  struct sockaddr_in servAddr;  /* remote server address */
  char buf[MAX_BUF_LEN];        /* buffer for transmission */
  unsigned int len;             /* length of the data to transmit */
  unsigned int bytesRcvd;       /* bytes read in single recv() call */
  unsigned int totalBytesRcvd;  /* total bytes read */
  struct hostent *server;       /* dns information of the server host */
  struct client_args *clntArgs; /* client thread arguments */
  int status;                   /* for pthread returns */
  
  /* Detach this thread from the main thread */
  status = pthread_detach(pthread_self());
  if(status != 0)
    err_abort(status, "Detach thread");
  
  /* Get the server arguments */
  if(args == NULL)
  {
    fprintf(stderr, "Client: invalid arguments\n");
    exit(EXIT_FAILURE);
  }
  clntArgs = (struct client_args*)args;
  
  /* gethostbyname takes a string like "www.domainame.com" or "localhost" and
   returns a struct hostent with DNS information; see man pages */
  server = gethostbyname(clntArgs->hostname);
  if(server == NULL)
    err_message("gethostbyname: could not find host");
  
  /* Create a reliable, stream socket using TCP */
  sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  if(sock < 0)
    err_message("socket() failed");

  /* Construct the server address structure */
  memset(&servAddr, 0x00, sizeof(servAddr));     /* clear the struct */
  memmove((char *) &servAddr.sin_addr.s_addr,
          (char *)server->h_addr,
          server->h_length);                     /* server IP address */
  servAddr.sin_family = AF_INET;                 /* Internet addr family */
  servAddr.sin_port   = htons(clntArgs->port);   /* server port */

  
  /* Establish the connection to the echo server */
  if(connect(sock, (struct sockaddr *) &servAddr, sizeof(servAddr)) < 0)
    err_message("connect() failed");
  
  /* Determine the data length */
  len = strlen(clntArgs->msg);
  
  /* Send the data to the server */
  if(send(sock, clntArgs->msg, len, 0) != len)
    err_message("send() failed");

  //RECEIVE RESPONSE HERE
  //TODO: should be piece size?
  totalBytesRcvd = 0;
  printf("[%s:%u]: ", inet_ntoa(servAddr.sin_addr), ntohs(servAddr.sin_port));
  while(totalBytesRcvd < len)
  {
    /* Receive up to the buffer size (minum one to leave space for a null
     terminator) bytes from the sender */
    if((bytesRcvd=recv(sock, buf, MAX_BUF_LEN-1, 0)) <= 0)
      err_message("recv() failed or connection closed prematurely");
    
    totalBytesRcvd += bytesRcvd;  /* keep tally of total bytes */
    buf[bytesRcvd] = 0;           /* terminate the c-string */
    printf("%s", buf);            /* print the buffer */
  }
  printf("\n");  /* final line feed */
  
  free(clntArgs);
  close(sock);
  
  return NULL;
}

void *client_thread_peer(void *args)
{
  int sock;                     /* socket descriptor */
  struct sockaddr_in servAddr;  /* remote server address */
  char buf[MAX_BUF_LEN];        /* buffer for transmission */
  unsigned int len;             /* length of the data to transmit */
  unsigned int bytesRcvd;       /* bytes read in single recv() call */
  unsigned int totalBytesRcvd;  /* total bytes read */
  struct hostent *server;       /* dns information of the server host */
  struct client_args *clntArgs; /* client thread arguments */
  struct peer_args *peerArgs;
  int status;                   /* for pthread returns */
  
  /* Detach this thread from the main thread */
  status = pthread_detach(pthread_self());
  if(status != 0)
    err_abort(status, "Detach thread");
  
  /* Get the server arguments */
  if(args == NULL)
  {
    fprintf(stderr, "Client: invalid arguments\n");
    exit(EXIT_FAILURE);
  }
  peerArgs = (struct peer_args*)args;
  clntArgs = (*client_args) malloc(sizeof(client_args));
  clntArgs->port = peerArgs->port;
  clntArgs->hostname = peerArgs->ip;

  //something like that... TODO
  Handshake hs(m_metaInfo.getHash(), "SIMPLEBT-TEST-PEERID");
  clntArgs->msg = (char *) hs.encode().data();
  
  /* gethostbyname takes a string like "www.domainame.com" or "localhost" and
   returns a struct hostent with DNS information; see man pages */
  server = gethostbyname(clntArgs->hostname);
  if(server == NULL)
    err_message("gethostbyname: could not find host");
  
  /* Create a reliable, stream socket using TCP */
  sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  if(sock < 0)
    err_message("socket() failed");

  /* Construct the server address structure */
  memset(&servAddr, 0x00, sizeof(servAddr));     /* clear the struct */
  memmove((char *) &servAddr.sin_addr.s_addr,
          (char *)server->h_addr,
          server->h_length);                     /* server IP address */
  servAddr.sin_family = AF_INET;                 /* Internet addr family */
  servAddr.sin_port   = htons(clntArgs->port);   /* server port */

  
  /* Establish the connection to the echo server */
  if(connect(sock, (struct sockaddr *) &servAddr, sizeof(servAddr)) < 0)
    err_message("connect() failed");
  
  /* Determine the data length */
  len = strlen(clntArgs->msg);
  
  /* Send the data to the server */
  if(send(sock, clntArgs->msg, len, 0) != len)
    err_message("send() failed");

  //RECEIVE HANDSHAKE HERE
  //TODO: should be piece size?

  /* Receive up to the buffer size (minum one to leave space for a null
   terminator) bytes from the sender */
  if((bytesRcvd=recv(sock, buf, MAX_BUF_LEN-1, 0)) <= 0)
    err_message("recv() failed or connection closed prematurely");
  
  Handshake received_hs;
  received_hs.decode(buf);

  printf("peerId:" + received_hs.getPeerId());  /* final line feed */
  

  //SEND BITFIELD
  Bitfield bf;
  //bf.setPayload()


  free(clntArgs);
  close(sock);
  
  return NULL;
}
