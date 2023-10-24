from scapy.all import RadioTap
from managers import stat_manager

class InputStream:
    def __init__(self):
        pass

    def process(self, data):
        frame = RadioTap(data)
        stat_manager.get().on_frame(frame)

input_stream = InputStream()
