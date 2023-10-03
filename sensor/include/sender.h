#ifndef SENDER_H
#define SENDER_H

#define WIDS_BUF_LEN 4096

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>

// TODO add a timestamp, and some logic around it, 
// so the data wont be stuck in the buffer forever in case of small traffic
typedef struct {
  int sock_fd;
  struct sockaddr_in serv_addr;
  int size_curr;                // how many butes of the buffer are used
  int size_total;               // what is the size of the buffer - WIDS_BUF_LEN
  char buffer[WIDS_BUF_LEN];    // buffer
} conn_t;

err_t setup_conn(conn_t *conn);
err_t _setup_udp(conn_t *conn);
err_t _setup_tcp(conn_t *conn);

err_t send_data(conn_t *conn, const char *data, int len);
err_t _send_udp(conn_t *conn);
err_t _send_tcp(conn_t *conn);

#endif
