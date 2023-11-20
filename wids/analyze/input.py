from scapy.all import RadioTap
from managers import stat_manager

class InputStream:
    def __init__(self):
        pass

    def process(self, data, sensor):
        frame = RadioTap(data)
        stat_manager.get().on_frame(frame, sensor=sensor)

input_stream = InputStream()
