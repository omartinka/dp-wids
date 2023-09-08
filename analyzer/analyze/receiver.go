package analyze

import (
  "wids/context"
  "wids/logging"

  "net"
  "fmt"
)

func initUDP() {
  log := logging.Get()
  udpAddr, err := net.ResolveUDPAddr("udp", context.Address)

  if err != nil {
    log.Fatal(err)
  }

  conn, err := net.ListenUDP("udp", udpAddr)
  if err != nil {
    log.Fatal(err)
  }

  defer conn.Close()

  log.Info(fmt.Sprintf("Listening on %s", context.Address))
  buffer := make([]byte, 65535)

  for {
    n, addr, err := conn.ReadFromUDP(buffer)
    if err != nil {
      log.Error(fmt.Sprintf("UDP recv error: %s", err))
      continue
    }

    recv := buffer[:n]
    log.Trace(fmt.Sprintf("[%s] %s", addr, recv))
  }
}

func initTCP() {
  return
}

func initWids() {
  if context.IsUdp {
    initUDP()
  } else if context.IsTcp {
    initTCP()
  }
}
