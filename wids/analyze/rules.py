import utils.context as ctx
import connectors.macapi

from managers.alert_manager import AlertManager
from managers import stat_manager
from scapy.all import RadioTap

import binascii

class Indicator:
    def __init__(self, data):
        self.iocs = []
        self.id = data['id']
        self.on = data['on']
        self.attributes = data['attrs']

    def _applicable(self, packet):
        for t_ in self.on:
            t, st = ctx.get_subtype_from_string(t_)
            if t == packet.type and st == packet.subtype:
                return True

        return False

    """
    for all _on* functions -> returns (bool, ioc)
    
    Note for future self: when addinf another _on_ functions, the return value is TRUE if 
    an indicator should be TRUE and therefore the rule should be applied.
    """
    def _on_ssid(self, packet, val):
        ssids, neg = ctx.get_config_ssids(val)
        ssid = packet.info.decode('utf-8', errors='ignore')
        ok = ssid in ssids
        if neg:
            ok = not ok
        return ok, [ssid]

    def _on_ssid_count(self, packet, attrs):
        sm = stat_manager.get()
        ssids = sm.get_ssids_for_channel(None)

        # if ssid being checked is `known`, do not generate an alert
        if packet.info.decode('utf-8', errors='ignore') in ssids:
            return False, []

        op = attrs['op'][0]
        count = int(attrs['op'][1:], 10)
        ignore_list = attrs['isnot']

        # check number of ssids other than `known`. if larger than a threshold, alert.
        ssids = [elem for elem in ssids if elem not in ignore_list]

        if op == '=' and len(ssids) == count:
            return (True, ssids)
        elif op == '<' and len(ssids) < count:
            return (True, ssids)
        elif op == '>' and len(ssids) > count:
            return (True, ssids)

        return False, []

    def _on_mac(self, packet, val):
        macs, neg = ctx.get_config_macs(val)
        bssid = packet.addr2
        ok = bssid in macs
        if neg:
            ok = not ok
        if ok:
            vendor = connectors.macapi.get_vendor(bssid)
        return ok, [bssid]

    def _on_auth_state(self, packet, val):
        sm = stat_manager.get()
        mac = packet.addr2 if packet.subtype == 0 else packet.addr3
        state = sm.get_state_for_addr(mac)

        iocs = []
        ok = state != val
        if ok:
            vendor = connectors.macapi.get_vendor(mac)
            iocs = [{"addr2": str(mac), "vendor": vendor}]
        return ok, iocs

    def _on_addr(self, packet, type_, val):
        to_check = packet.addr1
        if type_ == 'addr2':
            to_check = packet.addr2
        if type_ == 'addr3':
            to_check = packet.addr3

        macs, neg = ctx.get_config_macs(val)
        ok = to_check in macs
        if neg:
            ok = not ok
        return ok, [{type_: to_check}]

    def _on_channel(self, packet, val):
        channels = ctx.home_channels
        freq = packet.ChannelFrequency
        if freq is None:
            freq = 2447 # TODO FIX
        channel = ctx.get_channel_for_freq(freq)
        ssid = packet.info.decode('utf-8', errors='ignore')
        addr = packet.addr2
        ok = channel not in channels
        iocs = []
        
        if ok:
            vendor = connectors.macapi.get_vendor(addr)
            iocs = [{
                "ssid": ssid,
                "addr2": addr,
                "vendor": vendor,
                "channel": channel
            }]

        return ok, iocs

    def apply(self, packet):
        """ returns true if indicator applies to the packet """
        self.iocs = []
        for key in self.attributes:
            if not self._applicable(packet):
                 continue

            attrs = self.attributes[key]

            if key == 'ssid':
                ok, ioc = self._on_ssid(packet, self.attributes['ssid'])
                if not ok:
                    return False
                self.iocs += ioc

            if key == 'mac':
                ok, ioc = self._on_mac(packet, self.attributes['mac'])
                if not ok:
                    return False
                self.iocs += ioc

            if key == 'ssid-count':
                ok, ioc = self._on_ssid_count(packet, attrs)
                if not ok:
                    return False
                self.iocs += ioc

            if key == 'auth-state':
                ok, ioc = self._on_auth_state(packet, attrs)
                if not ok:
                    return False
                self.iocs += ioc

            if key in ['addr1', 'addr2', 'addr3']:
                ok, ioc = self._on_addr(packet, key, attrs)
                if not ok:
                    return False
                self.iocs += ioc

            if key == 'channel':
                ok, ioc = self._on_channel(packet, attrs)
                if not ok:
                    return False
                self.iocs += ioc

        self.iocs.sort(key=lambda x: str(x))
        return True

class Rule:
    def __init__(self, data):
        self.id = data['id']
        self.on = data['on']
        self.class_ = data['class']
        self.type = data['type']
        self.msg = data['msg']
        self.cooldown = self.__parse_cooldown(data['cooldown']) if 'cooldown' in data else None
        self.indicators = self._parse_indicators(data['indicators'])

    def __parse_cooldown(self, data):
        count = data[:-1]
        timetype = data[-1:]

        if timetype == 's':
            return int(count, 10)

        if timetype == 'm':
            return int(count, 10) * 60

        if timetype == 'h':
            return int(count, 10) * 60 * 60

        print('TODO XXX Rule.__parse_cooldown logovanie normalne nepoznam', timetype)
        return int(count, 10)

    def _generate_alert(self, packet, indicators, sensor):
        _alert = {
            "id": self.id,
            "class": self.class_,
            "type": self.type,
            "msg": self.msg,
            "indicators": [{"id": i.id, "iocs": i.iocs} for i in indicators],
            "raw_data": binascii.hexlify(bytes(packet)).decode(),
            "channel": ctx.get_channel_for_freq(packet.getlayer(RadioTap).ChannelFrequency if packet.getlayer(RadioTap).ChannelFrequency is not None else 2447) # TODO FIX
        }
        if sensor is not None:
            _alert['sensor'] = sensor
        return _alert

    def _parse_indicators(self, indicators):
        _indicators = []
        for i in indicators:
            _indicators.append(Indicator(i))
        return _indicators

    def _applicable(self, packet):
        """ returns true if rule is applicable on the packet
        """
        for t_ in self.on:
            t, st = ctx.get_subtype_from_string(t_)
            if t == packet.type and st == packet.subtype:
                return True

        return False


    def apply(self, packet, sensor):
        if not self._applicable(packet):
            return

        indicators = []
        for indicator in self.indicators:
            if indicator.apply(packet):
                indicators.append(indicator)

        if len(indicators):
            # Generate alert...
            alert = self._generate_alert(packet, indicators, sensor)
            AlertManager.get().alert(self, alert, 'alert')

