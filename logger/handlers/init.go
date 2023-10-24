package handlers

import (
  "wids/context"
  "wids/logging"
)

var log = logging.Get()
var dedup = NewDeduplicator()

func Init() {
  if context.Mode == context.OpTrace {
    // From file
    loadPcap()
  } 
}
