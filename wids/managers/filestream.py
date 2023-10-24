from scapy.all import PcapReader
from managers import stat_manager

class FileStream:

    def __init__(self):
        pass
    
    def process(self, file):
        pr = PcapReader(file)

        for packet in pr:    
            stat_manager.get().on_frame(packet)
            

file_stream = FileStream()
