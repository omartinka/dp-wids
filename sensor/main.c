#include "include/config.h"
#include "include/sniffer.h"
#include "include/sender.h"

int main(int argc, char *argv[]) {
  err_t err = parse_args(argc, argv);
  
  if (err != OK) {
    if (err == ERR_USAGE) {
      usage(argv[0]);
    }
    errmsg(err);
    return (int)err;
  }

  err = validate_interface();
  if (err != OK) {
    errmsg(err);
    return (int)err;
  }
  
  vlog(V_DEBUG, "connection init\n");
  conn_t conn;
  err = setup_conn(&conn);
  if (err != OK) {
    errmsg(err);
    return (int)err;
  }
  vlog(V_INFO, "started sniffing on interface %s\n", config->interface);
  err = sniff(&conn);
  vlog(V_INFO, "sniffing done\n");

  if (err != OK) {
    errmsg(err);
    return (int)err;
  }

  vlog(V_INFO, "all done.\n");
  return 0;
}
