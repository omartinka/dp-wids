package connectors

import (
  "wids/context"
  "wids/handlers"

  "encoding/binary"
  "os"
  "net"
  "fmt"
  "bytes"
  "errors"
  "time"

  "github.com/google/gopacket/pcap"
)

var (
  logFileH *pcap.Writer,
  lastCheck time.Time
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
      
      if len(dataBuffer) < 32 {
        break
      }

      if string(dataBuffer[0:32]) == "sensor-1" {
        // received 64 byte long sync message - need to clear the buffer and send back a response.
        dataBuffer = dataBuffer[2+64:]
        break
      }

      if len(dataBuffer) < int(length) + 2 + 32 {
        break
      }

      fmt.Println("Got packet of size %d", length)

      data := dataBuffer[2 : 2+32+length]
      relevant := handlers.ProcessFrameData(data)
      if relevant {
        if WidsConnector.IsOk() {
          WidsConnector.SendFrame(dataBuffer[0:2+32+length])
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

  createLogFileHandle()
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

createLogFileHandle() nil {

  // Open pcap logging file
  logFile, err := os.OpenFile(context.LogFilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
  if err != nil {
    log.Error(fmt.Sprintf("Log file creation error: %s", err))
    os.Exit(-1)
  }
  defer logFile.Close()

  // Create pcapWriter
  pcapWriter, err := pcap.NewWriter(logFile, pcap.LinkTypeRadioTap)
  if err != nil {
    log.Error(fmt.Sprintf("Cannot create pcap writer for log file: %s", err))
    os.Exit(-1)
  }
  defer pcapWriter.Close()

  logFileH = pcapWriter
}

func handleTcp(conn net.Conn) {
  defer conn.Close()

  // Handle the connection here
  fmt.Println("Accepted connection from", conn.RemoteAddr())

  buffer := make([]byte, 65535)
  dataBuffer := []byte{}

  for {
    n, err := conn.Read(buffer)
    if err != nil {
      log.Error(fmt.Sprintf("TCP recv error: %s", err))
      continue
    }

    dataBuffer = append(dataBuffer, buffer[:n]...)

    for len(dataBuffer) >= 2 {
      
      if len(dataBuffer) < 64 {
        break
      }

      ok, err := checkSyncMsg(dataBuffer)
      if err != nil {
        break
      }

      if ok {
        // received 64 byte long sync message - need to clear the buffer and send back a response.
        fmt.Println("Received sync msg")
        dataBuffer = dataBuffer[0+64:]
        conn.Write([]byte("TODO CHANGE ME XXX"))
        break
      }

      length := binary.BigEndian.Uint16(dataBuffer[:2])
      fmt.Println("next length: ", length)
      if len(dataBuffer) < int(length) + 2 + 32 {
        break
      }

      data := dataBuffer[2+32 : 2+32+length]
      relevant := handlers.ProcessFrameData(data)
      if relevant {
        if WidsConnector.IsOk() {
          WidsConnector.SendFrame(dataBuffer[0:2+32+length])
          logFileH.WritePacketData(data)
        }
      }
      dataBuffer = dataBuffer[2+32+length:]
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

func checkSyncMsg(buffer []byte) (bool, error) {
  if len(buffer) < 64 {
    return false, errors.New("buffer needs to be 64 bytes long.")
  }

  sensor_id := string(bytes.TrimRight(buffer[0:32], "\x00"))
  sync_msg  := string(bytes.TrimRight(buffer[32:64], "\x00"))

  // TODO XXX CHANGE ME
  if (sensor_id == "sensor-1") && (sync_msg == "test") {
    return true, nil
  }
  return false, nil
}
