#ifndef CONFIG_H
#define CONFIG_H

#define WIDS_ERR_SIZE 512

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
  ERR_UNKNOWN_VERBOSITY = 5,
  ERR_IF_NOT_FOUND = 6,
  ERR_PCAP_GENERIC = 7,
  ERR_VALIDATE_INTERFACE = 8,
  ERR_SNIFF = 9,
  ERR_GENERIC = 10
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
