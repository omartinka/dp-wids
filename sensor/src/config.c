#include "../include/config.h"

argstore_t __config = {0};
argstore_t *config = &__config;

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
  return;
}

err_t parse_args(int argc, char *argv[]) {
  int opt;

  while (opt != -1) {
    opt = getopt(argc, argv, "hu:t:v:i:d");
    switch (opt) {
      case 'h':
        return ERR_USAGE;
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
        config->daemon = atoi(optarg);
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
