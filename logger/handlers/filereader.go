package handlers

import (
  "wids/context"
  "github.com/google/gopacket/pcap"
  "github.com/google/gopacket"
)

func loadPcap() {
  
  handle, err := pcap.OpenOffline(context.InputTrace)
  if err != nil {
    log.Error(err) 
  }

  defer handle.Close()

  packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

  for packet := range packetSource.Packets() {
    processFrame(packet)
  }
}
