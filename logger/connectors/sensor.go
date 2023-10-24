package connectors

import (
  "wids/context"
  "wids/handlers"

  "encoding/binary"
  "os"
  "net"
  "fmt"
)

func initUDP() {
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
  dataBuffer := []byte{}

  for {
    n, _, err := conn.ReadFromUDP(buffer)
    if err != nil {
      log.Error(fmt.Sprintf("UDP recv error: %s", err))
      continue
    }

    dataBuffer = append(dataBuffer, buffer[:n]...)

    for len(dataBuffer) >= 2 {
      length := binary.BigEndian.Uint16(dataBuffer[:2])
      if len(dataBuffer) < int(length)+2 {
        break
      }

      fmt.Println("Got packet of size %d", length)

      data := dataBuffer[2 : 2+length]
      relevant := handlers.ProcessFrameData(data)
      if relevant {
        if WidsConnector.IsOk() {
          WidsConnector.SendFrame(dataBuffer[0:2+length])
        }
      }
      dataBuffer = dataBuffer[2+length:]
    }
  }
}


// TODO rewrite with my logging and remove unnecessary shit
func initTCP() {
  listener, err := net.Listen("tcp", context.Address)
  if err != nil {
      fmt.Println("Error listening:", err)
      os.Exit(1)
  }
  defer listener.Close()

  fmt.Println("Server is listening on", context.Address)

  for {
      // Accept incoming connections
      conn, err := listener.Accept()
      if err != nil {
          fmt.Println("Error accepting connection:", err)
          continue
      }

      go handleTcp(conn)
  }
}

func handleTcp(conn net.Conn) {
  defer conn.Close()

  // Handle the connection here
  fmt.Println("Accepted connection from", conn.RemoteAddr())

  // For simplicity, we'll just echo back any data received from the client
  buf := make([]byte, 1024)
  for {
      n, err := conn.Read(buf)
      if err != nil {
          fmt.Println("Error reading from connection:", err)
          break
      }

      data := buf[:n]
      fmt.Printf("Received data: %d\n", n)

      // Echo the data back to the client
      _, err = conn.Write(data)
      if err != nil {
          fmt.Println("Error writing to connection:", err)
          break
      }
  }

  fmt.Println("Connection closed")
}

func InitSensors() {
  if context.IsUdp {
    initUDP()
  } else if context.IsTcp {
    initTCP()
  }
}
