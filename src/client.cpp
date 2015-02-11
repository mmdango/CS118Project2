/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2014,  Regents of the University of California
 *
 * This file is part of Simple BT.
 * See AUTHORS.md for complete list of Simple BT authors and contributors.
 *
 * NSL is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * NSL is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * NSL, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 *
 * \author Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "client.hpp"
#include "server_thread.hpp"
#include "tracker-request-param.hpp"
#include "tracker-response.hpp"
#include "http/http-request.hpp"
#include "http/http-response.hpp"
#include "msg/msg-base.hpp"
#include "msg/handshake.hpp"
#include "errors.hpp" 
#include <fstream>
#include <boost/tokenizer.hpp>
#include <boost/lexical_cast.hpp>
#include <pthread.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>      /* for atoi() */
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>



namespace sbt {

  MetaInfo Client::m_metaInfo;
  std::vector<PeerInfo> Client::m_peers;

Client::Client(const std::string& port, const std::string& torrent)
  : m_interval(3600)
  , m_isFirstReq(true)
  , m_isFirstRes(true)
{
  srand(time(NULL));

  m_clientPort = boost::lexical_cast<uint16_t>(port);

  loadMetaInfo(torrent);

  run();
}

void
Client::run()
{
  while (true) {
    connectTracker();
    sendTrackerRequest();
    m_isFirstReq = false;
    recvTrackerResponse();
  printf("got here");


  int status;                    /* for pthread returns */
  pthread_t server, client;      /* server and client threads */
  struct server_args *servArgs;  /* server thread arguments */
  struct client_args *clntArgs;  /* client thread arguments */
  
  /* Start the server thread */
  servArgs = (struct server_args *)malloc(sizeof(struct server_args));
  servArgs->port = m_clientPort;
  servArgs->max_pending = 5;
  printf("got here");
  //status = pthread_create(&server, NULL, server_thread, servArgs);
  //if(status != 0)
  //  err_abort(status, "Server thread");
  sleep(1);
  
  /*
   * Initiate a client transmission of data
   *
  for (auto i = m_peers.begin(); i != m_peers.end(); i++) {

      // get client thread arguments 
      clntArgs = (struct client_args *)malloc(sizeof(struct client_args));
      clntArgs->port = i->port;
      memcpy(clntArgs->hostname, i->ip.c_str(), sizeof(*(i->ip.c_str())));
      
      //spawn new client thread 
      status = pthread_create(&client, NULL, client_thread_peer, clntArgs);
      if(status != 0)
        err_abort(status, "Client thread"); 
    }
*/
    close(m_trackerSock);
    sleep(m_interval);
  }
}

void
Client::loadMetaInfo(const std::string& torrent)
{
  std::ifstream is(torrent);
  m_metaInfo.wireDecode(is);

  std::string announce = m_metaInfo.getAnnounce();
  std::string url;
  std::string defaultPort;
  if (announce.substr(0, 5) == "https") {
    url = announce.substr(8);
    defaultPort = "443";
  }
  else if (announce.substr(0, 4) == "http") {
    url = announce.substr(7);
    defaultPort = "80";
  }
  else
    throw Error("Wrong tracker url, wrong scheme");

  size_t slashPos = url.find('/');
  if (slashPos == std::string::npos) {
    throw Error("Wrong tracker url, no file");
  }
  m_trackerFile = url.substr(slashPos);

  std::string host = url.substr(0, slashPos);

  size_t colonPos = host.find(':');
  if (colonPos == std::string::npos) {
    m_trackerHost = host;
    m_trackerPort = defaultPort;
  }
  else {
    m_trackerHost = host.substr(0, colonPos);
    m_trackerPort = host.substr(colonPos + 1);
  }
}

void
Client::connectTracker()
{
  m_trackerSock = socket(AF_INET, SOCK_STREAM, 0);

  struct addrinfo hints;
  struct addrinfo* res;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET; // IPv4
  hints.ai_socktype = SOCK_STREAM;

  // get address
  int status = 0;
  if ((status = getaddrinfo(m_trackerHost.c_str(), m_trackerPort.c_str(), &hints, &res)) != 0)
    throw Error("Cannot resolver tracker ip");

  struct sockaddr_in* ipv4 = (struct sockaddr_in*)res->ai_addr;
  char ipstr[INET_ADDRSTRLEN] = {'\0'};
  inet_ntop(res->ai_family, &(ipv4->sin_addr), ipstr, sizeof(ipstr));
  std::cout << "tracker address: " << ipstr << ":" << ntohs(ipv4->sin_port) << std::endl;

  if (connect(m_trackerSock, res->ai_addr, res->ai_addrlen) == -1) {
    perror("connect");
    throw Error("Cannot connect tracker");
  }

  freeaddrinfo(res);
}

void
Client::sendTrackerRequest()
{
  TrackerRequestParam param;

  param.setInfoHash(m_metaInfo.getHash());
  param.setPeerId("SIMPLEBT-TEST-PEERID"); //TODO:
  param.setIp("127.0.0.1"); //TODO:
  param.setPort(m_clientPort); //TODO:
  param.setUploaded(100); //TODO:
  param.setDownloaded(200); //TODO:
  param.setLeft(300); //TODO:
  if (m_isFirstReq)
    param.setEvent(TrackerRequestParam::STARTED);

  // std::string path = m_trackerFile;
  std::string path = m_metaInfo.getAnnounce();
  path += param.encode();

  HttpRequest request;
  request.setMethod(HttpRequest::GET);
  request.setHost(m_trackerHost);
  request.setPort(boost::lexical_cast<uint16_t>(m_trackerPort));
  request.setPath(path);
  request.setVersion("1.0");

  Buffer buffer(request.getTotalLength());

  request.formatRequest(reinterpret_cast<char *>(buffer.buf()));

  send(m_trackerSock, buffer.buf(), buffer.size(), 0);
}

void
Client::recvTrackerResponse()
{
  std::stringstream headerOs;
  std::stringstream bodyOs;

  char buf[512] = {0};
  char lastTree[3] = {0};

  bool hasEnd = false;
  bool hasParseHeader = false;
  HttpResponse response;

  uint64_t bodyLength = 0;

  while (true) {
    memset(buf, '\0', sizeof(buf));
    memcpy(buf, lastTree, 3);

    ssize_t res = recv(m_trackerSock, buf + 3, 512 - 3, 0);

    if (res == -1) {
      perror("recv");
      return;
    }

    const char* endline = 0;

    if (!hasEnd)
      endline = (const char*)memmem(buf, res, "\r\n\r\n", 4);

    if (endline != 0) {
      const char* headerEnd = endline + 4;

      headerOs.write(buf + 3, (endline + 4 - buf - 3));

      if (headerEnd < (buf + 3 + res)) {
        bodyOs.write(headerEnd, (buf + 3 + res - headerEnd));
      }

      hasEnd = true;
    }
    else {
      if (!hasEnd) {
        memcpy(lastTree, buf + res, 3);
        headerOs.write(buf + 3, res);
      }
      else
        bodyOs.write(buf + 3, res);
    }

    if (hasEnd) {
      if (!hasParseHeader) {
        response.parseResponse(headerOs.str().c_str(), headerOs.str().size());
        hasParseHeader = true;

        bodyLength = boost::lexical_cast<uint64_t>(response.findHeader("Content-Length"));
      }
    }

    if (hasParseHeader && bodyOs.str().size() >= bodyLength)
      break;
  }

  close(m_trackerSock);
  FD_CLR(m_trackerSock, &m_readSocks);


  bencoding::Dictionary dict;

  std::stringstream tss;
  tss.str(bodyOs.str());
  dict.wireDecode(tss);

  TrackerResponse trackerResponse;
  trackerResponse.decode(dict);
  m_peers = trackerResponse.getPeers();
  m_interval = trackerResponse.getInterval();

  if (m_isFirstRes) {
    for (const auto& peer : m_peers) {
      std::cout << peer.ip << ":" << peer.port << std::endl;
    }
  }

  m_isFirstRes = false;
}


void *Client::client_thread(void *args)
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

void *Client::client_thread_peer(void *args)
{
  int sock;                     /* socket descriptor */
  struct sockaddr_in servAddr;  /* remote server address */
  char buf[MAX_BUF_LEN];        /* buffer for transmission */
  unsigned int len;             /* length of the data to transmit */
  unsigned int bytesRcvd;       /* bytes read in single recv() call */
  struct hostent *server;       /* dns information of the server host */
  struct client_args *clntArgs; /* client thread arguments */
  struct peer_args *peerArgs;
  int status;                   /* for pthread returns */
  msg::HandShake hs(m_metaInfo.getHash(), "SIMPLEBT-TEST-PEERID");
  msg::HandShake received_hs;

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
  clntArgs = (client_args*) malloc(sizeof(client_args));
  clntArgs->port = peerArgs->port;
  memcpy(clntArgs->hostname, peerArgs->ip, sizeof(clntArgs->hostname));

  //something like that... TODO
  const char * msg = reinterpret_cast<const char *>((*hs.encode()).get());
  
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
  len = strlen(msg);
  
  /* Send the data to the server */
  if(send(sock, msg, len, 0) != len)
    err_message("send() failed");

  //RECEIVE HANDSHAKE HERE
  //TODO: should be piece size?

  /* Receive up to the buffer size (minum one to leave space for a null
   terminator) bytes from the sender */
  if((bytesRcvd=recv(sock, buf, MAX_BUF_LEN-1, 0)) <= 0)
    err_message("recv() failed or connection closed prematurely");
  
  //BufferPtr buf_ptr = std::make_shared<sbt::Buffer>(buf);
  //received_hs.decode(buf_ptr);

  printf("peerId:%s",received_hs.getPeerId().c_str());  /* final line feed */
  

  //SEND BITFIELD
  //Bitfield bf;
  //bf.setPayload()


  free(clntArgs);
  close(sock);
  
  return NULL;
}

} // namespace sbt
