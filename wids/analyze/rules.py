import utils.context as ctx
import utils.attributes
import utils.converters

import connectors.macapi

from managers.alert_manager import AlertManager
from managers import stat_manager, log_manager

from scapy.all import *
from typing import List

import binascii
import datetime
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

class IndicatorAttr:
    layer: Packet = None
    attr: str = None
    expr: str = None
    
    def __init__(self, data):
        self.layer = globals()[data['layer']]
        self.attr = data['attr']
        self.expr = data['expr']

    def __str__(self):
        return f"Attr(layer={self.layer}, attr={self.attr}, expr={self.expr})"

class IndicatorTime:
    month: List[str] = []
    day_week: List[str] = []
    day_month: List[str] = []
    hour: List[str] = []
    minute: List[str] = []
    
    def __init__(self, data):
        self.month = data.get('month', [])
        self.day_week = data.get('day_week', [])
        self.day_month = data.get('day_month', [])
        self.hour = data.get('hour', [])
        self.minute = data.get('minute', [])

    def __str__(self):
        return f"Time(month={self.month}, day_week={self.day_week}, day_month={self.day_month}, hour={self.hour}, minute={self.minute})"


class Indicator:
    id: int = 0
    on: List[Packet] = []
    cooldown: int = 0
    attrs: List[IndicatorAttr] = []
    times: List[IndicatorTime] = []

    def __init__(self, _idc):
        self.id = int(_idc['id'])
        self.on = []

        # layer objects instead of stirngs
        for _l in _idc['on']:
            self.on.append(globals()[_l])

        self.cooldown = _idc['cooldown']
        self._parse_attrs(_idc.get('attrs'))
        self._parse_time(_idc.get('time'))

        if 'state' in _idc:
            self.state = _idc['state']

    def __str__(self):
        return f"Indicator(id={self.id}, on={self.on}, cooldown={self.cooldown}, attrs={[str(x) for x in self.attrs]}, times={[str(x) for x in self.times]})"
    
    def _parse_time(self, time):
        self.times = []
        for t_ in time:
            self.times.append(IndicatorTime(t_))

    def _parse_attrs(self, attrs):
        self.attrs = []
        if attrs is None:
            return

        for attr in attrs:
            try:
                a = IndicatorAttr(attr)
                self.attrs.append(a)
            except Exception as e:
                log_manager.warn(f'Cannot parse attribute. error: {e} {attr}')

    def _applicable(self, packet: Packet):
        for layer in self.on:
            if packet.haslayer(layer):
                return True
        return False

    def apply(self, packet: Packet, sensor: str) -> List[Tuple[IndicatorAttr, any]]:
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
            str_ = utils.converters.parse_expr(atr, packet, sensor)
            apply = eval(str_)
            if not apply:
                return []

            iocs.append((atr.attr, getattr(packet, atr.attr)))

        # time
        if packet.time:
            date = datetime.datetime.fromtimestamp(float(packet.time))
            for time_ in self.times:
                for month in time_.month:
                    str_ = utils.converters.match_time(month, date.month)
                    if not eval(str_):
                        return []
                    iocs.append(("time_month", date.month))

                for day in time_.day_month:
                    str_ = utils.converters.match_time(day, date.day)
                    if not eval(str_):
                        return []
                    iocs.append(("time_day", date.day))

                for day in time_.day_week:
                    str_ = utils.converters.match_time(day, date.strftime('%A').lower())
                    if not eval(str_):
                        return []
                    iocs.append(("time_day_week", date.strftime('%A').lower()))

                for hour in time_.hour:
                    str_ = utils.converters.match_time(hour, date.hour)
                    if not eval(str_):
                        return []
                    iocs.append(('time_hour', date.hour))

                for minute in time_.minute:
                    str_ = utils.converters.match_time(minute, date.minute)
                    if not eval(str_):
                        return []
                    iocs.append(('time_minute', date.minute))

        return iocs

class Rule:
    def __init__(self, data):
        self.id = data["id"]
        self.on = []
        self.last_hit = float(0)

        for _l in data['on']:
            self.on.append(globals()[_l])

        self.class_ = data['class']
        self.type_ = 'rule'
        self.name = data['name']
        self.msg = data['msg']
        self.severity = data['severity']
        self.cooldown = ctx.parse_cooldown(data['cooldown']) if 'cooldown' in data else None
        self.indicators = self._parse_indicators(data['indicators'])

    def __str__(self):
        return f"Rule(id={self.id}, on={self.on}, class={self.class_}, type={self.type_}, name={self.name}, msg={self.msg}, severity={self.severity}, cooldown={self.cooldown}, indicators={[str(x) for x in self.indicators]})"

    def _parse_indicators(self, indicators):
        _indicators = []
        for i in indicators:
            _indicators.append(Indicator(i))
        return _indicators

    def _applicable(self, packet: Packet):
        """ checks whether a rule should be applied to a packet
              - enough time passed between rules as specified in rule definition
              - contains layers specified in rule 
        """
        if self.last_hit + self.cooldown > float(packet.time):
            return False

        for layer in self.on:
            if packet.haslayer(layer):
                return True
        return False

    def _generate_alert(self, packet: Packet, indicators: List[Tuple[Indicator, any]], sensor: str, frame_number: int):
        alert = ctx.alert_base(module=self, frame=packet, source=sensor, frame_number=frame_number)

        for indicator in indicators:
            inm, ioas = indicator
            for ioa in ioas:
                if inm.id not in alert['indicators']:
                    alert['indicators'][inm.id] = {}

                if ioa[0] in alert['indicators'][inm.id]:
                    alert['indicators'][inm.id][ioa[0]].update(ioa[1])

                alert['indicators'][inm.id][ioa[0]] = ioa[1]
        
        return alert

    def apply(self, packet, sensor, frame_number=None):
        if not self._applicable(packet):
            return

        indicators = []
        for indicator in self.indicators:
            iocs =  indicator.apply(packet, sensor)
            
            if len(iocs):
                indicators.append((indicator, iocs))

        if len(indicators):
            self.last_hit = float(packet.time)

            # Generate alert...
            alert = self._generate_alert(packet, indicators, sensor, frame_number=frame_number)
            return alert
        
        return None

