package context

import (
  "errors"
  "flag"
  "os"
  "fmt"

  "analyzer/logging"
)

var (
  GenerateProfile bool
  InputTrace      string

  flagAlias = map[string]string{
    "generate-profile": "g",
    "trace-file": "t",
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
    flag.Var(flagSet.Value, to, fmt.Sprintf("alias to %s", flagSet.Name))
	}
}

func checkDependencies() error {
  if GenerateProfile {
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
  }
  return nil;
}

func ParseArgs() {
  log := logging.Get()

  flag.BoolVar(&GenerateProfile, "generate-profile", false, "Generate a profile from a pcap")
  flag.StringVar(&InputTrace, "trace-file", "", "Pcap file to generate a profile from")

  addAliases()

  flag.Parse()

  err := checkDependencies();

  if err != nil {
    log.Error(err)
    log.Fatal("cli arg dependencies not met!")
  }

  log.Info("cli args parsed!")
}
