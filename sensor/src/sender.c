#include "../include/config.h"
#include "../include/sender.h"

err_t setup_conn(conn_t *conn) {
  conn->size_total = WIDS_BUF_LEN;
  conn->size_curr = 0;

  vlog(V_INFO, "frame length size is %d bytes\n", sizeof(uint16_t));
  
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
  conn->sock_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (conn->sock_fd == -1) {
    seterr("failed to create tcp socket");
    return ERR_GENERIC;
  }

  conn->serv_addr.sin_family = AF_INET;
  conn->serv_addr.sin_port = htons(config->port);

  if (inet_pton(AF_INET, config->addr, &conn->serv_addr.sin_addr) <= 0) {
    seterr("invalid address supplied: `%s`", config->addr);
    return ERR_GENERIC;
  }
  
  if (connect(conn->sock_fd, (struct sockaddr *)&conn->serv_addr, sizeof(conn->serv_addr)) == -1) {
    seterr("could not connect to server `%s`.", config->addr);
    return ERR_GENERIC;
  }

  return OK;
}

err_t send_data(conn_t *conn, const char *data, int _len) {
  if (!config->udp && !config->tcp) {
    seterr("no connection type supplied (needs tcp/udp!)");
    return ERR_GENERIC;
  }

  if (_len < 0) {
    seterr("send_data received negative length. error probably in sniffing.");
    return ERR_GENERIC;
  }
  
  int len = (uint16_t)_len;
  // if there is space in the buffer, fill it.
  if (sizeof(uint16_t) + len + conn->size_curr < conn->size_total) {
    // write the length of the frame so they can be disguished (is that a word?)
    uint16_t _nlen = htons(len);
    memcpy(conn->buffer + conn->size_curr, &_nlen, sizeof(uint16_t));
    conn->size_curr += sizeof(uint16_t);

    // write the length of the frame to first two bytes
    memcpy(conn->buffer + conn->size_curr, data, len);
    conn->size_curr += len;
    vlog(V_TRACE, "appending data to buffer, length: %d->%d/%d\n", conn->size_curr-len, conn->size_curr, conn->size_total);
    return OK;
  }

  // if there is no space in the buffer, send the contents
  err_t err;
  if (config->udp) {
    err = _send_udp(conn);
    if (err != OK) {
      seterr("failed to send udp data in _send_udp, sender.c!");
      return ERR_GENERIC;
    }
  }
  
  if (config->tcp) {
    err = _send_tcp(conn);
    if (err != OK) {
      seterr("failed to send tcp data in _send_tcp, sender.c!");
      return ERR_GENERIC;
    }
  }

  // reset buffer
  int _bytes_sent = conn->size_curr;
  conn->size_curr = 0;
  
  // write the length of the frame
  uint16_t _nlen = htons(len);
  memcpy(conn->buffer + conn->size_curr, &_nlen, sizeof(uint16_t));
  conn->size_curr += sizeof(uint16_t);
  
  // write new data to 'empty' buffer
  vlog(V_DEBUG, "sent %d bytes, buffer now: %d->%d.\n", _bytes_sent, conn->size_curr, conn->size_curr+len);
  memcpy(conn->buffer+conn->size_curr, data, len);
  conn->size_curr += len;

  return OK;
}

err_t _send_udp(conn_t *conn) {
  // TODO utlize `buffer` and `curr` in conn_t struct to send `WIDS_BUF_LEN` frames at once

  ssize_t sent_bytes = sendto(
    conn->sock_fd,
    conn->buffer,
    conn->size_curr,
    0,
    (const struct sockaddr *)&conn->serv_addr,
    sizeof(conn->serv_addr)
  );

  if (sent_bytes == -1) {
    seterr("failed to send udp data to `%s:%d`", config->addr, config->port);
    return ERR_GENERIC;
  }

  return OK;
}

err_t _send_tcp(conn_t *conn) {
  ssize_t total_sent = 0;
  while (total_sent < conn->size_curr) {
    ssize_t sent_bytes = send(conn->sock_fd, conn->buffer, conn->size_curr, 0);
    if (sent_bytes == -1) {
      seterr("failed to send tcp data `to `%s:%d`", config->addr, config->port);
      return ERR_GENERIC;
    }
    total_sent += sent_bytes;
  }
  return OK;
}
