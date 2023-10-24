package main

import (
  "wids/context"
  "wids/logging"
  "wids/connectors"
  "wids/handlers"
)

func main() {
  // setup application logging
  logging.Init()
  
  // parse arguments and load global variables 
  context.Init()

  // connect to sensors, analyzer if in wids mode
  connectors.Init()

  // run the app
  handlers.Init()
}
