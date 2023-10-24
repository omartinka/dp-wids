package handlers

import (
    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
)

/*
 * Processes frame data gotten from sensors nodes
 * 
 * returns: True if frame is relevant to the WIDS, false otherwise
 */
func ProcessFrameData(data []byte) bool {
  packet := gopacket.NewPacket(data, layers.LayerTypeRadioTap, gopacket.NoCopy)
  relevant := processFrame(packet)
  return relevant
}

func isDuplicate(channel uint16, seqnum uint16) bool {
  present := dedup.Check(int(channel), int(seqnum))
  dedup.Add(int(channel), int(seqnum))
  return present
}

func freqToChannel(freq uint16) uint16 {
  if freq < 3000 {
    return (freq - 2400) / 5
  } else {
    return (freq - 5000) / 5
  }
  // mam pici wifi 6 zatial
}

/*
 * Processes frame data gotten from trace files
 * 
 * Performs simple checks to figure out whether the frame is relevant to the WIDS
 *  - checks whether it is a duplicate                                (20/80)
 *  - control frames are irrelevant as of now                         (0/100)
 *  - data bursts are irrelevant, only one data frame needed for wids (0/100)
 *
 * returns: true if frame is relevant, false otherwise
 */
func processFrame(frame gopacket.Packet) bool {
  radioTapLayer := frame.Layer(layers.LayerTypeRadioTap)
  radiotap, _ := radioTapLayer.(*layers.RadioTap)
  dot11Layer := frame.Layer(layers.LayerTypeDot11)
  dot11 := dot11Layer.(*layers.Dot11)
  seqnum := dot11.SequenceNumber
  
  // if sequence number is not zero, check for duplicacy
  if seqnum != 0 {
    channel_ := radiotap.ChannelFrequency
    channel := uint16(channel_)
    channel = freqToChannel(channel)
    dup := isDuplicate(channel, seqnum)
    if (dup) {
      return false
    }
  }

  // if no checks determined frame is irrelevant, return true
  return true
}

