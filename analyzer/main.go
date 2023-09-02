package main

import (
  "analyzer/context"
  "analyzer/logging"
)

func main() {
  logging.Init()

  context.ParseArgs()
}
