#include "include/config.h"
#include "include/sniffer.h"
#include "include/sender.h"

int main(int argc, char *argv[]) {
  err_t err = parse_args(argc, argv);
  
  if (err != OK) {
    errmsg(err);
    usage(argv[0]);
    return (int)err;
  }
  
  vlog(V_NONE, "none test\n");
  vlog(V_ERROR, "error test\n");
  vlog(V_INFO, "info test\n");
  vlog(V_DEBUG, "debug test\n");

  return 0;
}
