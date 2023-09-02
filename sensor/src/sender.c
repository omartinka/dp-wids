#include "../include/config.h"
#include "../include/sender.h"

err_t setup_conn(conn_t *conn) {
  if (config->tcp) {
    return _setup_tcp(conn);
  }

  if (config->udp) {
    return _setup_udp(conn);
  }
}

err_t _setup_udp(conn_t *conn) {

  conn->sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (conn->sock_fd == -1) {
    seterr("failed to create udp socket");
    return ERR_GENERIC;
  }

  conn->serv_addr.sin_family = AF_INET;
  conn->serv_addr.sin_port = htons(config->port);

  if (inet_pton(AF_INET, config->addr, &conn->serv_addr.sin_addr) <= 0) {
    seterr("invalid address supplied: `%s`", config->addr);
    return ERR_GENERIC;
  }
  
  return OK;
}

err_t _setup_tcp(conn_t *conn) {
  return ERR_GENERIC;
}

err_t send_data(conn_t *conn, const char *data, int len) {
  if (config->udp) {
    return _send_udp(conn, data, len);
  }
  
  if (config->tcp) {
    return _send_tcp(conn, data, len);
  }

  seterr("no connection type supplied (needs tcp/udp!)");
  return ERR_GENERIC;
}

err_t _send_udp(conn_t *conn, const char *data, int len) {
  // TODO utlize `buffer` and `curr` in conn_t struct to send `WIDS_BUF_LEN` frames at once

  ssize_t sent_bytes = sendto(
    conn->sock_fd,
    data,
    len,
    0,
    (const struct sockaddr *)&conn->serv_addr,
    sizeof(conn->serv_addr)
  );

  if (sent_bytes == -1) {
    seterr("failed to send udp data `%s` to `%s:%d`", data, config->addr, config->port);
    return ERR_GENERIC;
  }

  return OK;
}

err_t _send_tcp(conn_t *conn, const char *data, int len) {
  seterr("not implemented.");
  return ERR_GENERIC;
}
