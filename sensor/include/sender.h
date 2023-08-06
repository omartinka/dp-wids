#ifndef SENDER_H
#define SENDER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

typedef struct {
  int sock_fd;
  struct sockaddr_in serv_addr;
} conn_t;

err_t setup_conn(conn_t *conn);
err_t _setup_udp(conn_t *conn);
err_t _setup_tcp(conn_t *conn);

err_t send_data(conn_t *conn, const char *data, int len);
err_t _send_udp(conn_t *conn, const char *data, int len);
err_t _send_tcp(conn_t *conn, const char *data, int len);

#endif
