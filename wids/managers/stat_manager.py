import utils.context as ctx
from scapy.all import *
import time
import logging as log

from utils.config import config
from utils.queue import Queue

logging.basicConfig(level=logging.DEBUG)

class AuthTable:
    def __init__(self):
        self.auth_table = {}

    def get(self):
        return self.auth_table

    def update_entry(self, addr, data):
        entry = self.auth_table.get(addr)

        if entry is None:
            self.auth_table[addr] = {
                'time': time.time(),
                'state': data
            }
        
        else:
            # TODO maybe check if state changing is ok ?
            # like raise an alert if auth request without assoc and that
            entry['state'] = data
            entry['time'] = time.time()

    def get_state_for_addr(self, addr):
        entry = self.auth_table.get(addr)
        if entry is None:
            return None

        return entry['state']


class StatManager():
    def __init__(self):
        self.learning = False
        # self.queue = []
        self.queue = Queue(config.keep_for, self._remove_frame)
        self.auth_table = AuthTable()

        self.ssids = {}
        self.aps = {}
        self.occurences = {}
        self.sta_state = {}
        self.total = 0
        self.start = time.time()

    def state_for(self, client_addr, ap_addr):
        return None

    def __on_management(self, frame, remove):
        freq = frame.getlayer(RadioTap).ChannelFrequency
        if freq is None:
            freq = 2447
        channel = ctx.get_channel_for_freq(freq)
        if channel not in self.ssids:
            self.ssids[channel] = {}
        if channel not in self.aps:
            self.aps[channel] = {}

        # beacon
        if frame.subtype == ctx.SUBTYPE_BEACON:
            ssid = frame.info.decode('utf-8', errors='ignore')
            interval = frame.getlayer(Dot11Beacon).beacon_interval
            timestamp = frame.time
            bssid = frame.addr3

            if not remove:
                if ssid not in self.ssids[channel]:
                    self.ssids[channel][ssid] = 1
                
                if bssid not in self.aps[channel]:
                    self.aps[channel][bssid] = {
                        'ssid': ssid,
                        'expected_interval': interval,
                        'expected_rssi': frame.dBm_AntSignal,
                        'last_beacon': timestamp,
                        'last_num': frame.SC,
                        'count': 1
                    }

            if remove:
                if ssid in self.ssids[channel]:
                    self.ssids[channel][ssid] -= 1
                    if self.ssids[channel][ssid] <= 0:
                        del self.ssids[channel][ssid]
                
                if bssid in self.aps[channel]:
                    me = self.aps[channel][bssid]
                    me['count'] -= 1
                    me['last_beacon'] = timestamp
                    if me['count'] <= 0:
                        del self.aps[channel][bssid] # me may work ?

        # assoc request
        if frame.subtype == 0:
            self.auth_table.update_entry(frame.addr2, 'assoc-req')
            self.sta_state[frame.addr2] = 'assoc-req'
        
        # assoc response
        if frame.subtype == 1:
            self.auth_table.update_entry(frame.addr3, 'associated')
            self.sta_state[frame.addr1] = 'associated'

        # open authentication
        if frame.subtype == 0x0b:
            self.auth_table.update_entry(frame.addr2, 'open-auth')
            self.sta_state[frame.addr3] = 'open-auth'

        # EAPOL
        if frame.subtype == 0x08:
            # TODO specific eapol messages
            self.auth_table.update_entry(frame.addr2, 'eapol')
            self.sta_state[frame.addr2] = 'eapol'

        # Dissasociation
        if frame.subtype == ctx.STYPE_DISASS:
            self.sta_state[frame.addr1] = 'disassociated'

        # Deauthentication
        if frame.subtype == ctx.STYPE_DEAUTH:
            self.sta_state[frame.addr1] = 'deauthenticated'

    def __on_data(self, frame, remove):
        if frame.subtype == 8:
            # EAPOL
            pass

    def __update_occurences(self, frame, remove):
        freq = frame.getlayer(RadioTap).ChannelFrequency
        if freq is None:
            freq = 2447
        channel = ctx.get_channel_for_freq(freq)
        if channel not in self.occurences:
            self.occurences[channel] = {}

        val = -1 if remove else 1

        if self.occurences[channel].get(frame.type) is None:
            self.occurences[channel][frame.type] = {}
        if self.occurences[channel][frame.type].get(frame.subtype) is None:
            self.occurences[channel][frame.type][frame.subtype] = 0

        self.occurences[channel][frame.type][frame.subtype] += val

    def _analyze_frame(self, frame, remove=False):
        if frame.type == ctx.TYPE_MGMT:
            self.__on_management(frame, remove)
        elif frame.type == ctx.TYPE_DATA:
            self.__on_data(frame, remove)

        self.__update_occurences(frame, remove)

    def _add_frame(self, frame):
        """ this shit is surely inefficient, fix it """
        self.queue.append(frame)
        
        self.total += 1

        if self.total % 10000 == 0:
            end = time.time()
            print(f'[info] processed 10000 frames in {end - self.start}, items in queue: {len(self.queue)}')
            self.start = end

        self._analyze_frame(frame, remove=False)
        
    def _remove_frame(self, to_remove):
        if not isinstance(to_remove, list):
            to_remove = [to_remove]
        
        for frame in to_remove:
            self._analyze_frame(frame, remove=True)

    def __calc_thresholds(self):
        """ goes over the values learned in learning phase and calculates averages
        and thresholds that are to be compared in rule matching to raise alerts
        """ 
        pass

    def __learn(self, frame):
        curr_time = time.time()
        if curr_time - self.start > ctx.learning_for:
            self.learning = False
            self.__calc_thresholds()
            return
        
        rtp_layer = frame.getLayer(RadioTap)
        rssi = rtp_layer.dBm_AntSignal
        addr = rtp_layer.addr2
        
        if addr not in self.rssi_table:
            self.rssi_table[addr] = [rssi]
        else:
            self.rssi_table[addr].append(rssi)

    def on_frame(self, frame, sensor, frame_number=None):
        if self.learning:
            self.__learn(frame)
        
        self._add_frame(frame)

stat_manager = StatManager()

def get():
    return stat_manager
