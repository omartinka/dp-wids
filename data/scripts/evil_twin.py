#! /usr/bin/env python3
from scapy.all import RadioTap, Dot11, Dot11Beacon, Dot11Elt, wrpcap

beacon_packets = []

aps = [{
    "ssid": "evil-twin-1",
    "mac": "00:00:de:ad:be:ef"
}, {
    "ssid": "evil-twin-1",
    "mac": "00:00:ca:fe:ba:be"
}]

for i in range(20):
    ap = aps[i % 2]
    beacon = RadioTap() / Dot11(type=0, subtype=8, addr2=ap['mac']) / Dot11Beacon() / Dot11Elt(ID=0, info=ap['ssid'])
    beacon_packets.append(beacon)

# Save the beacon packets to a .pcap file
wrpcap("sample_beacon_packets.pcap", beacon_packets)
