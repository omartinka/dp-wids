#ifndef CONFIG_H
#define CONFIG_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

typedef enum {
  OK = 0,
  ERR_USAGE = 1,
  ERR_BOTH_CONN_TYPES = 2,
  ERR_CONN_TYPE_NOT_SUPPLIED = 3,
  ERR_INTERFACE_NOT_SUPPLIED = 4,
  ERR_UNKNOWN_VERBOSITY = 5
} err_t;

typedef struct {
  int daemon;
  int tcp;
  int udp;
  char *addr;
  char *interface;
  int verbosity;
} argstore_t;

extern argstore_t __config;
extern argstore_t *config;

void usage(const char *name);
void errmsg(err_t _err);

err_t parse_args(int argc, char *argv[]);

#endif
