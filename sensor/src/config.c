#include "../include/config.h"

argstore_t __config = {0};
argstore_t *config = &__config;

const char *__color_red    = "\033[31m";
const char *__color_blue   = "\033[34m";
const char *__color_yellow = "\033[33m";
const char *__color_reset  = "\033[0m";

/* 
 * Logging function with verbosity parameter 
 * 
 * @_verbosity: specifies the verbosity level - V_ERROR, V_INFO or V_DEBUG
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
    }
    vprintf(format, args);
    va_end(args);
  }
}

void usage(const char *program_name) {
    printf("Usage: %s -i <interface> [-u <ip> | -t <ip>] [-v <0-3>] [-d] [-h]\n", program_name);
    printf("Options:\n");
    printf("  -i <interface>     Specify the interface to listen on (required)\n");
    printf("  -u <ip:port>       Use UDP to transfer frames to specified IP address and port\n");
    printf("  -t <ip:port>       Use TCP to transfer frames and specify the listen IP address and port\n");
    printf("  -v <0-3>           Set verbosity level (0-3)\n");
    printf("  -d                 Run as a daemon\n");
    printf("  -h                 Display help message and exit\n");
}

void errmsg(err_t _err) {
  vlog(V_ERROR, "program failed with error code %d\n", _err);
  return;
}

err_t parse_args(int argc, char *argv[]) {
  int opt = 0;

  while (opt != -1) {
    opt = getopt(argc, argv, "hu:t:v:i:d");
    switch (opt) {
      case 'h':
        return ERR_USAGE;
      case 'i':
        config->interface = optarg;
        break;
      case 'u':
        config->udp = 1;
        config->addr = optarg;
        break;
      case 't':
        config->tcp = 1;
        config->addr = optarg;
        break;
      case 'v':
        config->verbosity = atoi(optarg);
        break;
      case 'd':
        config->daemon = 1;
        break;
      default:
        break;
    }
  }

  if (config->tcp && config->udp) {
    return ERR_BOTH_CONN_TYPES;
  }

  if (config->interface == NULL) {
    return ERR_INTERFACE_NOT_SUPPLIED;
  }

  if (config->tcp + config->udp != 1) {
    return ERR_CONN_TYPE_NOT_SUPPLIED;
  }

  if (config->verbosity < 0 || config->verbosity > 3) {
    return ERR_UNKNOWN_VERBOSITY; 
  }

  return OK;
}
