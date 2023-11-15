#ifndef CONFIG_H
#define CONFIG_H

#define WIDS_ERR_SIZE 512

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>

typedef enum {
  OK = 0,
  ERR_USAGE = 1,
  ERR = 2,
  ERR_GENERIC = 3
} err_t;

typedef enum {
  V_NONE = 0,   // no output
  V_ERROR = 1,  // only errors
  V_INFO = 2,   // 
  V_DEBUG = 3,  // garbage but helpful
  V_TRACE = 4   // bunch of bullshit, worthless in most cases
} verbosity_t;

typedef struct {
  int daemon;
  int tcp;
  int udp;
  char *addr;
  int port;
  char *interface;
  int verbosity;
  char sensor_id[32];
  char hello_msg[32];

  int sensor_id_len;
} argstore_t;

extern char _errmsg[WIDS_ERR_SIZE];
extern argstore_t __config;
extern argstore_t *config;

extern const char* __color_red;
extern const char* __color_blue;
extern const char* __color_yellow;
extern const char* __color_red;

void vlog(verbosity_t _verbosity, const char *format, ...);
void usage(const char *name);
void seterr(const char *format, ...);
void errmsg(err_t _err);

err_t parse_args(int argc, char *argv[]);

#endif
