import utils.context as ctx
from managers.rule_manager import rule_parser
from scapy.all import *

class StatTable:
    def __init__(self):
        self.stat_table = {
            "ssid": {}
        }

    def get(self):
        return self.stat_table

    def add_ssid_entry(self, ssid, expected_interval, timestamp, remove):
        if self.stat_table["ssid"].get(ssid) is None:
            self.stat_table["ssid"][ssid] = {
                'expected_interval': expected_interval,
                'last_beacon': timestamp,
                'beacon_count': 1
            }
            return
        
        mydict = self.stat_table["ssid"][ssid]
        mydict['last_beacon'] = ssid
        
        if not remove:
            mydict['beacon_count'] += 1
        else:
            mydict['beacon_count'] -= 1

        if mydict['beacon_count'] == 0:
            del self.stat_table["ssid"][ssid]

class StatManager():
    def __init__(self):
        self.stat_table = StatTable()
        self.queue = []

    def __on_management(self, frame, remove):

        # beacon
        if frame.subtype == 8:
            ssid = frame.info.decode('utf-8', errors='ignore')
            interval = frame.getlayer(Dot11Beacon).beacon_interval
            timestamp = frame.getlayer(Dot11Beacon).timestamp
            self.stat_table.add_ssid_entry(ssid, interval, timestamp, remove)

    def __analyze_frame(self, frame, remove=False):
        if frame.type == 0:
            self.__on_management(frame, remove)



    def __add_frame(self, frame):
        """ this shit is surely inefficient, fix it """
        self.queue.append(frame)
        if len(self.queue) > ctx.QUEUE_LEN:
            to_remove = seff.queue[:-ctx.QIEIE_LEN]
            self.queue = self.queue[-ctx.QUEUE_LEN:]
            self.__remove_frame(to_remove)

        self.__analyze_frame(frame, remove=False)
        

    def __remove_frame(self, to_remove):
        if not isinstance(to_remove, list):
            to_remove = [to_remove]
        
        for frame in to_remove:
            self.__analyze_frame(frame, remove=True)

    def on_frame(self, frame):
        # first check rules
        for rule in rule_parser.rules:
            rule.apply(frame)
        
        # then add
        self.__add_frame(frame)

    def get_ssids_for_channel(self, channel):
        # ignore the channel for now this is a prototype
        return [key for key in self.stat_table.get()['ssid']]

stat_manager = StatManager()

def get():
    return stat_manager
