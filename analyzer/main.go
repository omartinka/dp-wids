package main

import (
  "wids/context"
  "wids/logging"
  "wids/analyze"
)

func main() {
  logging.Init()

  context.Init()

  analyze.Init()
}
