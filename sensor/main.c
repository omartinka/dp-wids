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
  return 0;
}
