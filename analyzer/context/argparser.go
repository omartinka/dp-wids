package context

import (
  "errors"
  "flag"
  "os"
  "fmt"

  "wids/logging"
)

var (
  Mode            int          // 0 - active WIDS, 1 - trace analysis, 2 - generate profile
  InputTrace      string
  IsUdp           bool
  IsTcp           bool
  Address         string
  Profile         string

  flagAlias = map[string]string{
    "mode": "m",
    "trace-file": "t",
    "udp": "u",
    "address": "a",
  }
)

func addAliases() {
  log := logging.Get()
	for from, to := range flagAlias {
		flagSet := flag.Lookup(from)
    if flagSet == nil {
      log.Debug(fmt.Sprintf("trying to add an alias for undefined flag %s (alias %s) - skipping", from, to))
      continue
    }
    // desc := fmt.Sprintf("alias to %s", flagSet.Name)
    flag.Var(flagSet.Value, to, "")
	}
}

func checkDependencies() error {
  /* 
   * Dependencies if generating a profile
   */
  if Mode == 2 {
    if InputTrace == "" {
      return errors.New("please provide a trace file (--trace-file) when generating a profile!")
    }

    if InputTrace != "" {
      _, err := os.Stat(InputTrace)
      if err != nil {
        errmsg := fmt.Sprintf("cannot access trace file `%s`. does it exist?", InputTrace)
        return errors.New(errmsg)
      }
    }
  } else if Mode == 0 {
    /*
     * Dependencies in real time WIDS mode
     */
    if (IsUdp && IsTcp) || (!IsUdp && !IsTcp) {
      errmsg := "choose either udp or tcp, not both"
      return errors.New(errmsg)
    }
  } else if Mode == 1 {
    /*
     * Dependencies in trace file analysis mode
     */
  } else {
    /*
     * monkey
     */
    return errors.New("invalid mode specified!")
  }

  return nil;
}

func parseArgs() {
  log := logging.Get()

  flag.IntVar(&Mode, "mode", 0, "Specify operation mode of the analyzer. Available modes: \n    1: active WIDS\n    2: trace file analysis\n    3: profile generation")
  flag.StringVar(&InputTrace, "trace-file", "", "Pcap file to generate a profile from")

  flag.BoolVar(&IsUdp, "udp", false, "Use UDP socket as a data source")
  flag.BoolVar(&IsTcp, "tcp", false, "Use TCP to connect to sensor/s as a data source/s")
  flag.StringVar(&Address, "address", "", "Address to listen on (udp) / connect back to (tcp).\nUse format `address:port`.\nIf using multiple sensors over TCP, specify their addresses separated by a comma\n     example: `addr1:port1,addr2:port2`")
  flag.StringVar(&Profile, "profile", "", "Profile file/directory used in instrusion detecion")

  addAliases()

  flag.Parse()

  err := checkDependencies();

  if err != nil {
    log.Error(err)
    log.Fatal("cli arg dependencies not met!")
  }

  log.Info("cli args parsed!")
}
