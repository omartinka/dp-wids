import utils.context as ctx
from managers.rule_manager import rule_parser
from scapy.all import *
import time
import logging as log

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


class StatTable:
    def __init__(self):
        self.stat_table = {
            "ssid": {}
        }

    def get(self):
        return self.stat_table

    def add_ssid_entry(self, channel, ssid, expected_interval, timestamp, remove):
        if self.stat_table["ssid"].get(ssid) is None:
            log.debug(f'new ssid entry {ssid} on channel {channel}!')
            self.stat_table["ssid"][ssid] = {
                'expected_interval': expected_interval,
                'last_beacon': timestamp,
                'beacon_count': 1,
                'channels': {channel: 1}
            }
            return
        
        mydict = self.stat_table["ssid"][ssid]
        mydict['last_beacon'] = ssid

        if not remove:
            mydict['beacon_count'] += 1

            if channel in mydict['channels']:
                mydict['channels'][channel] += 1
            else:
                log.debug(f'new channel for ssid {ssid}! {channel}')
                mydict['channels'][channel] = 1

        else:
            mydict['beacon_count'] -= 1

            if channel in mydict['channels']:
                mydict['channels'][channel] -= 1

        if mydict['beacon_count'] == 0:
            del self.stat_table["ssid"][ssid]

class StatManager():
    def __init__(self):
        self.stat_table = StatTable()
        self.auth_table = AuthTable()
        self.queue = []
        self.rssi_table = {}

        self.learning = False # TODO will be true somewhen
        self.start = time.time()

        self.rssi = {
            "avg": 0,
            "threshold": 0,
        }

    def __on_management(self, frame, remove):
        freq = frame.getlayer(RadioTap).ChannelFrequency
        if freq is None:
            freq = 2447
        channel = ctx.get_channel_for_freq(freq)

        # beacon
        if frame.subtype == 8:
            ssid = frame.info.decode('utf-8', errors='ignore')
            interval = frame.getlayer(Dot11Beacon).beacon_interval
            timestamp = frame.getlayer(Dot11Beacon).timestamp
            self.stat_table.add_ssid_entry(channel, ssid, interval, timestamp, remove)

        # assoc
        if frame.subtype == 0:
            self.auth_table.update_entry(frame.addr2, 'assoc-req')
        
        if frame.subtype == 1:
            self.auth_table.update_entry(frame.addr3, 'associated')

        if frame.subtype == 0x0b:
            self.auth_table.update_entry(frame.addr2, 'open-auth')

        if frame.subtype == 0x08:
            # TODO specific eapol messages
            self.auth_table.update_entry(frame.addr2, 'eapol')

    def __on_data(self, frame, remove):
        if frame.subtype == 0:
            pass

    def __analyze_frame(self, frame, remove=False):
        if frame.type == 0:
            self.__on_management(frame, remove)
        elif frame.type == 2:
            self.__on_data(frame, remove)

    def __add_frame(self, frame):
        """ this shit is surely inefficient, fix it """
        self.queue.append(frame)
        if len(self.queue) > ctx.QUEUE_LEN:
            to_remove = self.queue[:-ctx.QUEUE_LEN]
            self.queue = self.queue[-ctx.QUEUE_LEN:]
            self.__remove_frame(to_remove)

        self.__analyze_frame(frame, remove=False)
        
    def __remove_frame(self, to_remove):
        if not isinstance(to_remove, list):
            to_remove = [to_remove]
        
        for frame in to_remove:
            self.__analyze_frame(frame, remove=True)

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

    def on_frame(self, frame, sensor):

        if self.learning:
            self.__learn(frame)

        if not self.learning:
            for rule in rule_parser.rules:
                rule.apply(frame, sensor=sensor)
        
        # then add
        self.__add_frame(frame)

    def get_ssids_for_channel(self, channel):
        # ignore the channel for now this is a prototype
        return [key for key in self.stat_table.get()['ssid']]

    def get_state_for_addr(self, addr):
        return self.auth_table.get_state_for_addr(addr)

stat_manager = StatManager()

def get():
    return stat_manager
