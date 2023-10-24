package connectors

import (
  "wids/context"
  "wids/logging"
)

var log = logging.Get()

/* 
 * Initializes connectors
 *
 * If the app is running as WIDS, connect to sensors and the analyzer
 * If app is analyzing a trace file, no connectors are loaded,
 * the output is just a carved trace file.
 *
 */
func Init() {
  if context.Mode == context.OpWids {
    InitWidsConn()
    InitSensors()
  }
}

