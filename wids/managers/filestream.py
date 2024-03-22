from scapy.all import PcapReader
from analyze import processor

class FileStream:
    
    shutdown_flag = False

    def __init__(self):
        pass

    def kill(self):
        self.shutdown_flag = True
    
    def process(self, file):
        processor.init()

        pr = PcapReader(file)
        source = file.split('/')[-1]

        for i, packet in enumerate(pr):
            if self.shutdown_flag:
                return

            processor.get().process(packet, source, frame_number=i+1)

file_stream = FileStream()
