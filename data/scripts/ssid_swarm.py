#! /usr/bin/env python3
from scapy.all import RadioTap, Dot11, Dot11Beacon, Dot11Elt, wrpcap
import random
import uuid

beacon_packets = []

def generate_mac():
    return ':'.join([f'{octet:02x}' for octet in [random.randint(0x00, 0xff) for _ in range(6)]])

def generate_uuid():
    return str(uuid.uuid1())


macs  = []
uuids = []
for _ in range(12):
    macs.append(generate_mac())
    uuids.append(generate_uuid())

packets = []
for _ in range(100):
    for i in range(12):
        beacon = RadioTap() / Dot11(type=0, subtype=8, addr2=macs[i]) / Dot11Beacon() / Dot11Elt(ID=0, info=uuids[i])
        packets.append(beacon)

wrpcap("sample_ssid_swarm", packets)
