import utils.context as ctx
import connectors.macapi

from managers.alert_manager import AlertManager
from managers import stat_manager, log_manager
from scapy.all import *

import binascii
import logging as log


table = {
    "asso-req": Dot11AssoReq,
    "asso-resp": Dot11AssoResp,
    "reasso-req": Dot11ReassoReq,
    "reasso-resp": Dot11ReassoResp,
    "auth": Dot11Auth,
    "eapol": EAPOL,
    "eapol-key": EAPOL_KEY
}


class Attribute:
    layer: Packet = None # idkkk
    attr: str = None
    op: str = None
    val: str|int = None
    fluctuation: int = None

    def __init__(self, data):
        self.layer = globals()[data['layer']]
        self.attr = data['attr']
        self.op = data['operation']
        self.val = data['value']
        self.action = data['on_missing'] if 'on_missing' in data else 'ignore'
        self.fluctuation = data['fluctuation'] if 'fluctuation' in data else 0
        self._check()

    def _check(self):
        if self.op not in ['==', '!=', '>', '<', '<=', '>=', 'in', '!in']:
            raise Exception('unknown operation')
        if self.action not in ['ignore', 'alert', 'log']:
            raise Exception('unknown action.')

class Indicator:

    def __init__(self, _idc):
        self.id = _idc['id']
        self.on = []

        # layer objects instead of stirngs
        for _l in _idc['on']:
            self.on.append(globals()[_l])

        self.cooldown = _idc['cooldown']
        self._parse_attrs(_idc['attrs'])

        if 'state' in _idc:
            self.state = _idc['state']

    def _parse_attrs(self, attrs):
        self.attrs = []
        for attr in attrs:
            try:
                a = Attribute(attr)
                self.attrs.append(a)
            except Exception as e:
                log_manager.warn(f'Cannot parse attribute. error: {e} {attr}')

    def _applicable(self, packet: Packet):
        for layer in self.on:
            if packet.haslayer(layer):
                return True
        return False

    def apply(self, packet: Packet) -> List[Tuple[Attribute, any]]:
        if not self._applicable(packet):
            return []

        iocs = []

        # attrs
        for atr in self.attrs:
            if not packet.haslayer(atr.layer):
                # acto on action
                return []
            
            if not hasattr(packet, atr.attr):
                # act on action
                return []

            val = getattr(packet, atr.attr)
            
            if atr.op == '==' and atr.val != val:
                return []
            elif atr.op == '!=' and atr.val == val:
                return []
            elif atr.op == '>' and atr.val <= val:
                return []
            elif atr.op == '<' and atr.val >= val:
                return []
            elif atr.op == '>=' and atr.val < val:
                return []
            elif atr.op == '<=' and atr.val > val:
                return []
            elif atr.op == 'in' and val not in atr.val:
                return []
            elif atr.op == '!in' and val in atr.val:
                return []

            iocs.append((atr.attr, val))
        
        # check authentication state
        # if self.state is not None:
        #     sm = stat_manager.get_instance()
        #     if sm.state_for(packet.addr2, packet.addr3) in self.state:
        #         iocs.append(('auth_state', sm.state_for(packet.addr2)))
        
        # if len(iocs):
        #     sm = stat_manager.get_instance()
            # iocs.append('state', sm.state_for(packet.addr2, packet.addr3))

        return iocs

class Rule:
    def __init__(self, data):
        self.id = data['id']
        self.on = []

        for _l in data['on']:
            self.on.append(globals()[_l])

        self.class_ = data['class']
        self.type = data['type']
        self.msg = data['msg']
        self.cooldown = ctx.parse_cooldown(data['cooldown']) if 'cooldown' in data else None
        self.indicators = self._parse_indicators(data['indicators'])

        self._last_cooldown = None

    def _parse_indicators(self, indicators):
        _indicators = []
        for i in indicators:
            _indicators.append(Indicator(i))
        return _indicators

    def _applicable(self, packet: Packet):
        """ check if the packet has layers specified in rule """
        for layer in self.on:
            if packet.haslayer(layer):
                return True
        return False

    def _generate_alert(self, packet: Packet, indicators: List[Tuple[Indicator, any]], sensor: str, frame_number: int):
        # TODO 
        alert = utils.alert_base()
        
        return alert

    def apply(self, packet, sensor, frame_number=None):
        if not self._applicable(packet):
            return

        indicators = []
        for indicator in self.indicators:
            iocs =  indicator.apply(packet)
            
            if len(iocs):
                indicators.append((indicator, iocs))

        if len(indicators):
            # Generate alert...
            alert = self._generate_alert(packet, indicators, sensor, frame_number=frame_number)
            return alert
        
        return None

