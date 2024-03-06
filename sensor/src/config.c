#include "../include/config.h"

char _errmsg[WIDS_ERR_SIZE] = {0};
const char *__color_red    = "\033[31m";
const char *__color_blue   = "\033[34m";
const char *__color_yellow = "\033[33m";
const char *__color_gray   = "\033[90m";
const char *__color_reset  = "\033[0m";

argstore_t __config = {0};
argstore_t *config = &__config;

/* 
 * Logging function with verbosity parameter 
 * 
 * @_verbosity: specifies the verbosity level - V_ERROR, V_INFO, V_DEBUG or V_TRACE
 * @_format: string format, rest is just as in printf()
 */
void vlog(verbosity_t _verbosity, const char *format, ...) {
  if (config->verbosity >= (int)_verbosity && config->verbosity != V_NONE && _verbosity != V_NONE) {
    va_list args;
    va_start(args, format);
    switch(_verbosity) {
      case V_ERROR:
        printf("%s[error]%s ", __color_red, __color_reset);
        break;
      case V_INFO:
        printf("%s[info]%s  ", __color_blue, __color_reset);
        break;
      case V_DEBUG:
        printf("%s[debug]%s ", __color_yellow, __color_reset);
        break;
      case V_TRACE:
        printf("%s[trace]%s", __color_gray, __color_reset);
        break;
    }
    vprintf(format, args);
    va_end(args);
  }
}

void usage(const char *program_name) {
    printf("Usage: %s [ options ]\n", program_name);
    printf("Options:\n");
    printf("  -i <interface> Specify the interface to listen on (r)\n");
    printf("  -u             Use UDP for communication [broken] (r0*)\n");
    printf("  -t             Use TCP for communication (r0*)\n");
    printf("  -a <addr>      IP/hostname of logger module (r)\n");
    printf("  -p <port>      Port of logger module (r)\n");
    printf("  -n <name>      Identification name of sensor node (r)\n");
    printf("  -m <msg>       Initialization message for module synchronization (r)\n");
    printf("  -v <0-4>       Set verbosity level (0-4)\n");
    printf("  -d             Run as a daemon\n");
    printf("  -h             Display help message and exit\n");
    printf("\n");
    printf("Info:\n");
    printf(" - options labeled as (r) are required\n");
    printf(" - at least one of options labeled as (r[x]*) is required per [x]\n");
}

void seterr(const char *format, ...) {
  va_list args;
  va_start(args, format);
  vsnprintf(_errmsg, WIDS_ERR_SIZE, format, args);
  va_end(args);
}

void errmsg(err_t _err) {
  vlog(V_ERROR, "program failed with error code %d\n", _err);
  if (_errmsg[0] != 0) {
    vlog(V_ERROR, "description: %s\n", _errmsg);
  } else {
    vlog(V_ERROR, "no error description supplied\n");
  }
  return;
}

err_t parse_args(int argc, char *argv[]) {
  int opt = 0;

  if (argc < 2) {
    usage(argv[0]);
    return ERR_USAGE;
  }
  
  // default values
  config->verbosity = 3;
  uint32_t _len = 0;

  while (opt != -1) {
    opt = getopt(argc, argv, "huta:p:v:i:dn:m:");
    switch (opt) {
      case 'h':
        return ERR_USAGE;
      case 'i':
        config->interface = optarg;
        break;
      case 'u':
        config->udp = 1;
        break;
      case 't':
        config->tcp = 1;
        break;
      case 'a':
        config->addr = optarg;
        break;
      case 'p':
        config->port = atoi(optarg);
        break;
      case 'v':
        config->verbosity = atoi(optarg);
        break;
      case 'd':
        config->daemon = 1;
        break;
      case 'n':
        _len=strlen(optarg);
        if (_len > 32) {
          vlog(V_INFO, "provided sensor ID has length %d, trunctating to 32.\n", _len);
          _len = 32;
        }
        vlog(V_INFO, "sensor id of length %d\n", _len);
        config->sensor_id_len = _len;
        memcpy(config->sensor_id, optarg, _len);
        break;
      case 'm':
        _len=strlen(optarg);
        if (_len > 32) {
          vlog(V_INFO, "provided sync message has length %d, trunctating to 32.\n", _len);
          _len = 32;
        }
        memcpy(config->hello_msg, optarg, _len);
        break;
      default:
        break;
    }
  }

  if (config->tcp && config->udp) {
    seterr("only one connection type needs to be supploed! (got both udp and tcp!)");
    return ERR;
  }

  if (config->addr == NULL) {
    seterr("logger module not specified! (use -a)");
    return ERR;
  }

  if (config->interface == NULL) {
    seterr("no network interface supplied! (use `-i`)");
    return ERR;
  }

  if (config->tcp + config->udp != 1) {
    seterr("no connection type supplied!");
    return ERR;
  }

  if (config->verbosity < 0 || config->verbosity > 4) {
    seterr("unknown verbosity. use values 0-4");
    return ERR; 
  }

  if (config->port <= 0 || config->port > 65535) {
    seterr("port needs to be 1-65535, not `%d.`", config->port);
    return ERR;
  }

  if (config->sensor_id == NULL) {
    seterr("sensor ID not set!");
    return ERR;
  }

  int _sensor_id_len = strlen(config->sensor_id);
  if (_sensor_id_len > 32) {
    _sensor_id_len = 32;
  }
  config->sensor_id_len = _sensor_id_len;

  if (config->hello_msg == NULL) {
    seterr("hello msg not set!");
    return ERR;
  }

  return OK;
}
