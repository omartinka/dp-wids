package logging

import (
  "github.com/sirupsen/logrus"
  "os"
)

var log = logrus.New()

func Init() {
  log.Out = os.Stdout

  log.SetFormatter(&logrus.TextFormatter{
    DisableColors: false,
    FullTimestamp: true,
  })

  log.SetLevel(logrus.TraceLevel)
}

func Get() *logrus.Logger {
  return log
}
