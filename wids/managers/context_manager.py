""" 

Stores the virtual map of the 'network'

Every nearby device: 
 - state for every home AP
 - RSSI for every sensor
 - (maybe?) histogram of message types
 - [TODO !!!] - make 'aggregator' node send special message on long data streams - optimization

All nearby networks
 - 
    

"""

from utils.config import config

from typing import Tuple, List
from scapy.all import Packet
import enum

class DeviceState(enum.Enum):
    pass

class RSSI:
    min:  int = 892384
    max:  int = -772381
    last: int = 0

    def __init__(self, rssi: int):
        self.last = rssi
        self.update(rssi)

    def update(self, rssi: int):
        if rssi < self.min:
            self.min = rssi
        if rssi > self.max:
            self.max = rssi

    def __str__(self):
        return f"RSSI(min={self.min}, max={self.max}, last={self.last})"

# TODO make enum or smth
class State:
    UNKNOWN = 0

class _Device:
    index: int = 0

    # MAC of the device
    mac: str = ""

    # State for each AP
    state: dict[str, str] = {}

    # RSSI for each sensor
    rssi: dict[str, RSSI] = {}
    
    def __init__(self, mac: str, rssi: int, sensor: str) -> None:
        self.state = {}
        self.rssi = {}
        self.mac = mac
        self.rssi[sensor] = RSSI(rssi)
        self.index = _Device.index + 1
        _Device.index += 1

    def __str__(self):
        _s = f" => Device {self.index}:\n"
        _s += f"""    MAC: {self.mac}
    State: {self.state}
    RSSI: 
  """
        for key in self.rssi:
            _s += f"    [sensor: {key}]: {self.rssi[key]}"
        return _s

class _Network:
    pass

class ContextManager:
    _devices: dict[str, _Device] = {}

    def __init__(self):
        self._devices = {}

    def on_frame(self, frame: Packet, sensor: str, frame_number: int = None) -> None:
        # if frame is not relevant to home networks, ignore
        home_macs = config.home.macs()
        if frame.addr2 not in home_macs and frame.addr3 not in home_macs:
            return

        device = frame.addr2
        rssi = frame.dBm_AntSignal

        if device not in self._devices:
            _d = _Device(device, rssi, sensor)
            self._devices[device] = _d

        else:
            _d = self._devices[device]
            if sensor not in _d.rssi:
                _d.rssi[sensor] = RSSI(rssi)
            else:
                _d.rssi[sensor].update(rssi)

            if frame.addr3 in config.home:
                _d.state[frame.addr3] = State.UNKNOWN

    def summary(self):
        print('Devices:')
        for key in self._devices:
            print(f'{self._devices[key]}')

context_manager = ContextManager()

def get():
    return context_manager
