from scapy.all import PcapReader
from analyze import processor

class FileStream:

    def __init__(self):
        pass
    
    def process(self, file):
        pr = PcapReader(file)
        source = file.split('/')[-1]

        for i, packet in enumerate(pr):
            processor.get().process(packet, source, frame_number=i+1)


file_stream = FileStream()
