from scapy.all import *

class NetworkMap():
    def __init__(self):
        self.network_map = {}
    

    def add_beacon(self, channel, ssid, interval, frame_len):
        for _channel in network_map:
            if _channel.get('ssid') is not None:
                # the same SSID in multiple channels
                pass
            

        if channel not in self.network_map:
            self.network_map[channel] = set()

        if ssid not in self.network_map[channel]

class Profiler():

    def __init__(self):
        pass

    def make_profile(self, capture, max_packets):
        stream = rdpcap(capture)

        for packet in stream:
            if packet.haslayer(RadioTap) and packet.haslayer(Dot11Beacon):
                beacon = packet[Dot11Beacon]
                ssid = beacon.info.decode()
                freq = packet[RadioTap].ChannelFrequency
                
                if freq > 5000:
                    freq = (freq - 5000) // 5
                print(ssid, freq)

profiler = Profiler()
