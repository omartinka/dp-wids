from scapy.all import PcapReader
from managers import stat_manager

class FileStream:

    def __init__(self):
        pass
    
    def process(self, file):
        pr = PcapReader(file)
        print('pcap loaded.')

        for i, packet in enumerate(pr):
            stat_manager.get().on_frame(packet, 'tracefile')
            

file_stream = FileStream()
