package handlers

/*
 * Profile generation
 * scans an ordinary trace file with no intrusions and generates a `profile` file
 * which is used as a base of an ordinary traffic, so the IDS can determine anomalies
 */

import (
  "github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
  "wids/context"
)


func processFrame_(frame gopacket.Packet) {
  log.Trace(frame)
}

func generateProfile() error {
  path := context.InputTrace

  handle, err := pcap.OpenOffline(path)
  if err != nil {
    log.Fatal(err)
  }
  defer handle.Close()

  packetSrc := gopacket.NewPacketSource(handle, handle.LinkType())

  for frame := range packetSrc.Packets() {
    processFrame_(frame)
  }

  return nil
}


