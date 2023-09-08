package analyze

import (
  "wids/context"
)


func Init() {
  if context.Mode == 0 {
    // WIDS
    initWids()
  } else if context.Mode == 1 {
    // From file

  } else if context.Mode == 2 {
    // Generate profile
    generateProfile()
  }
}
