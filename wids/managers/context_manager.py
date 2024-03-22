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
from managers import log_manager
import utils.converters

from utils.const import *
from utils.attributes import is_frame, state_for_type, State, get_eapol_state

from typing import Tuple, List, Set
from scapy.all import Packet
from scapy.layers.dot11 import *
from scapy.layers.eap import *

import enum
import time
import datetime
import copy
import math

class RSSI:
    min:  int = 892384    # 
    max:  int = -772381   # 
    last: int = 0         # last rssi
    jump: int = 0         # last jump
    biggest_jump: int = 0 # biggest jump recorded ever world record woaw
    ok: bool = False      # false if first meranie true otherwise

    def __init__(self, rssi: int):
        self.last = rssi
        self.update(rssi)

    def update(self, rssi: int):
        if rssi < self.min:
            self.min = rssi
        if rssi > self.max:
            self.max = rssi

        if abs(rssi - self.last) > self.biggest_jump:
            self.biggest_jump = abs(rssi - self.last)
        
        if self.ok:
            self.jump = rssi - self.last

        self.last = rssi
        self.ok = True


    def __str__(self):
        return f"RSSI(min={self.min}, max={self.max}, last={self.last}, jump={self.jump}, big_jump={self.biggest_jump})"


class _Device:

    class AP_():
        def __init__(self, state=State.unknown, cipher=0):
            self.state: State  = state
            self.cipher: int = cipher

        def __str__(self):
            return f"(state={self.state.name}, cipher={RSN[self.cipher]})"

    class DeviceState_(dict):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)

        def set_state(self, ap: str=None, state: State=None):

            if self.get(ap) is None:
                self[ap] = _Device.AP_(state=state)
                return

            if state == State.unknown:
                if self[ap].state == None:
                    self[ap].state = state
                return

            self[ap].state = state

        def set_cipher(self, ap: str, cipher: int):
            if self.get(ap) is None:
                self[ap] = _Device.AP_(state=State.unknown, cipher=cipher)
                return
            self[ap].cipher = cipher

    index: int = 0

    def __init__(self, mac: str) -> None:


        # MAC of the device
        self.mac: str = ""

        # State for each AP
        self.state: _Device.DeviceState_[str, State] = _Device.DeviceState_()

        # RSSI for each sensor
        self.rssi: dict[str, RSSI] = {}

        # time when was the device last seen
        self.last_seen: float = 0.0
        self.rssi = {}
        self.mac = mac
        self.index = _Device.index + 1

        _Device.index += 1

    def __str__(self):
        _s = f" => Device {self.index}:\n"
        _s += f"    MAC: {self.mac}\n"
        _s += f"    State:\n"
        for key in self.state:
            _s += f"      [AP: {key}]: {self.state[key]}\n"
        _s += f"    RSSI:\n"
        for key in self.rssi:
            _s += f"      [sensor: {key}]: {self.rssi[key]}\n"
        _s += f"    Last seen: {str(datetime.datetime.fromtimestamp(self.last_seen))}\n"
        return _s

    def in_(self, sensor: str) -> bool:
        return sensor in self.rssi

class _Network:
    hidden: bool = False
    ssid: str = ""
    beacon_interval: int = 0
    mac: Set[str] = set()
    last_beacon: int = 0

    def __init__(self):
        pass

class ContextManager:

    learning: bool = False

    def __init__(self):
        self._devices = {}
        self._networks: dict[str, _Network]
        self._devices: dict[str, _Device] = {}
        self._total_frames: int = 0
        self._last_frame_num: int = 0
        self._started_at: float = time.time() 

    def _debug_on(self, n, *args, **kwargs) -> bool:
        if self._last_frame_num == n:
            log_manager.debug(*args, **kwargs)
            return True
        return False

    def _update_device(self, frame: Packet, sensor: str) -> _Device:
        src = frame.addr2
        
        # Irrelevant frame
        if src in ['ff:ff:ff:ff:ff:ff', None] or src in config.home.macs():
            return None

        if src not in self._devices:
            self._devices[src] = _Device(src)
        
        _d = self._devices[src]
        _d.last_seen = float(frame.time)

        rssi = frame.dBm_AntSignal
        if sensor not in _d.rssi:
            _d.rssi[sensor] = RSSI(rssi)
        else:
            _d.rssi[sensor].update(rssi)

        dst = frame.addr1
        if dst in config.home.macs():
            if (frame.type, frame.subtype) in [F_REASSOREQ, F_ASSOREQ]:
                if frame.haslayer(RSNCipherSuite):
                    cipher = frame[RSNCipherSuite].cipher
                    _d.state.set_cipher(ap=dst, cipher=cipher)

        return _d

    def on_frame(self, frame: Packet, sensor: str, frame_number: int = None) -> None:
        """ updates internal network image state - does not do any intrusion detecion """
        self._last_frame_num = frame_number

        # if frame is not relevant to home networks, ignore
        home_macs = config.home.macs()
        frame_addrs = [frame.addr1, frame.addr2, frame.addr3]

        if len(set(home_macs).intersection(set(frame_addrs))) == 0:
            return

        src = frame.addr2
        dst = frame.addr1

        if src is None:
            return
        
        # Update device info
        device = self._update_device(frame, sensor)

        # Update state
        self._update_state(frame, sensor)

        # Advertising - beacon or probe:
        # TODO XXX if frame sbtype is probe or beacon
        # if False:
        #     ssid = ""
        #     hidden = false
        #     beacon_interval = 0
        #     mac = 0
        #     
        #     if mac in self._networks:
        #         self._networks[mac].update(ssid, hidden, beacon_interval, mac)

        #     net = _Network()
        #     self._networks[mac] = net

        # self._update_state(frame)
        self._total_frames += 1


    def _update_state(self, frame: Packet, sensor) -> None:
        src = frame.addr2
        dst = frame.addr1

        # AP --> BROADCAST
        if src in config.home.macs() and dst == 'ff:ff:ff:ff:ff:ff':
            ok, tt = is_frame(frame, [F_DEAUTH, F_DISASS])
            if not ok:
                return
            
            # Update state for all devices
            for key in self._devices:
                device = self._devices.get(key)
                if not device.in_(sensor):
                    continue

                if not device or device.last_seen < float(frame.time) - config.left_after:
                    continue

                device.state.set_state(src, state_for_type(tt))
            return

        # AP --> DEVICE
        if src in config.home.macs() and dst in self._devices:
            ok, tt = is_frame(frame, [F_ASSORESP, F_REASSORESP, F_AUTH, F_EAPOL, F_DEAUTH, F_DISASS])
            if not ok:
                return

            dev_ = self._devices.get(dst)
            if dev_ is None:
                return

            state_ = state_for_type(tt)
            if state_ == State.eapol_1:
                state_ = get_eapol_state(frame)

            dev_.state.set_state(src, state_)
            return

        # DEVICE --> AP
        if src in self._devices and dst in config.home.macs():
            ok, tt = is_frame(frame, [F_ASSOREQ, F_REASSOREQ, F_DEAUTH, F_DISASS, F_AUTH, F_EAPOL])
            if not ok:
                return

            dev_ = self._devices.get(src)
            if dev_ is None:
                return

            state_ = state_for_type(tt)
            if state_ == State.eapol_1:
                state_ = get_eapol_state(frame)

            dev_.state.set_state(dst, state_)

    ##                                            ##
    #  Information functions for user interaction  #
    ##                                            ##

    def info_devices(self):
        print('Devices:')
        for key in self._devices:
            if len(self._devices[key].state):
                print(f'{self._devices[key]}')
    
    def info_networks(self):
        print('Networks:')
        print('  --> TODO <--')
    
    def info_summary(self):
        now = time.time()
        print(f"analyzed: {self._total_frames}, skipped: {self._last_frame_num - self._total_frames}. total: {self._last_frame_num}, time: {round(now - self._started_at, 2)} seconds.")

    def info_config(self):
        config.summary()

    ##                                   ##
    #  Getters used in detection modules  #
    ##                                   ##

    def state(self, device: str, ap: str) -> State:
        """ Get state of device <device> for AP <ap> """
        dev = self._devices.get(device)
        if not dev:
            return None
        client_state = dev.state.get(ap, None)
        return copy.deepcopy(client_state)

    def rssi(self, device: str, sensor: str) -> RSSI:
        """ Get RSSI of device <device> for sensor <sensor> """
        dev = self._devices.get(device)
        return None if dev is None else dev.rssi.get(sensor)

    def last_seen(self, device: str) -> float:
        """ Get last seen time of device <device> """
        dev = self._devices.get(device)
        return None if dev is None else dev.last_seen

    def devices(self) -> List[str]:
        return self._devices.keys()

context_manager = ContextManager()

def get():
    return context_manager
