#ifndef CONFIG_H
#define CONFIG_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>

typedef enum {
  OK = 0,
  ERR_USAGE = 1,
  ERR_BOTH_CONN_TYPES = 2,
  ERR_CONN_TYPE_NOT_SUPPLIED = 3,
  ERR_INTERFACE_NOT_SUPPLIED = 4,
  ERR_UNKNOWN_VERBOSITY = 5
} err_t;

typedef enum {
  V_NONE = 0,
  V_ERROR = 1,
  V_INFO = 2,
  V_DEBUG = 3
} verbosity_t;

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

extern const char* __color_red;
extern const char* __color_blue;
extern const char* __color_yellow;
extern const char* __color_red;

void vlog(verbosity_t _verbosity, const char *format, ...);
void usage(const char *name);
void errmsg(err_t _err);

err_t parse_args(int argc, char *argv[]);

#endif
