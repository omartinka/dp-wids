package context

import (
  "errors"
  "flag"
  "os"
  "fmt"
  "time"

  "wids/logging"
)

const (
  OpWids    = 0
  OpClean   = 1
)

var (
  Mode            int    // 0: active WIDS, 1: trace file clean-up
  InputTrace      string // Input trace file for clean up
  Address         string // Address on which to listen on
  WidsAddress     string // Address of WIDS
  LogFilePath     string // Where to store raw pcap logs
  OutputPath      string // Output for cleaned trace file

  log = logging.Get()
  flagAlias = map[string]string{
    "mode": "m",
    "trace-file": "t",
    "address": "l",
    "wids": "w",
    "logfilepath": "p",
    "outputpath": "o"
  }
)

func setDefault() {
  Mode = OpWids
  InputTrace = ""
  Address = ""
  WidsAddress = "localhost:1234"
  logFilePath = ""
  OutputPath = ""
}

func addAliases() {
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
   * Dependencies if cleaning up a trace file
   */
  if Mode == OpClean {
    if InputTrace == "" {
      return errors.New("please provide a trace file (--trace-file)!")
    }

    if InputTrace != "" {
      _, err := os.Stat(InputTrace)
      if err != nil {
        errmsg := fmt.Sprintf("cannot access trace file `%s`. does it exist?", InputTrace)
        return errors.New(errmsg)
      }
    }
  } else if Mode == OpWids {
    /*
     * Dependencies in real time WIDS mode
     */
    if (DoLog) {
      if LogFilePath == "" {
        currTime := time.Now()
        LogFilePath = fmt.Sprintf("trace-%04d-%02d-%02d.pcap", currTime.Year(), currTime.Month(), currTime.Day())
        log.Info(fmt.Sprintf("log file path not specified, defaulting to `%s`.", LogFilePath))

      // check access to specified log file
      f, err := os.OpenFile(LogFilePath, os.O_WRONLY, os.ModeAppend)
      if err != nil {
        return err
      }
      defer f.Close()
    }
  } else {
    return errors.New("invalid mode specified!")
  }

  return nil;
}

func parseArgs() {
  setDefault()

  flag.IntVar(&Mode, "mode", 0, "Specify operation mode of the analyzer. Available modes: \n    1: active WIDS\n    2: trace file analysis\n    3: profile generation")
  flag.StringVar(&InputTrace, "trace-file", "", "Pcap file to generate a profile from")

  flag.BoolVar(&IsUdp, "udp", false, "Use UDP socket as a data source")
  flag.BoolVar(&IsTcp, "tcp", false, "Use TCP to connect to sensor/s as a data source/s")
  flag.StringVar(&Address, "address", "", "Address to listen on (udp) / connect back to (tcp).\nUse format `address:port`.\nIf using multiple sensors over TCP, specify their addresses separated by a comma\n     example: `addr1:port1,addr2:port2`")
  flag.StringVar(&Profile, "profile", "", "Profile file/directory used in instrusion detecion")
  flag.StringVar(&WidsAddress, "wids-address", "", "Address of WIDS to send data to.")

  flag.BoolVar(&DoLog, "log", false, "Enable logging of raw pcap traffic")
  flag.StringVar(&LogFilePath, "logfile", "Path for raw pcap file")
  
  addAliases()

  flag.Parse()
  IsTcpWids = true
  err := checkDependencies();

  if err != nil {
    log.Error(err)
    log.Fatal("cli arg dependencies not met!")
  }

  log.Info("cli args parsed!")
}
