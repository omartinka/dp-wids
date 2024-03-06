import modules.base
import utils.context as context
from utils.const import *

from utils.config import config
from managers.stat_manager import StatManager
from scapy.all import Packet


class FloodModule(modules.base.BaseModule):
    """ Module for detection of TODO Attacks """
    def __init__(self, module_id: int):
        super().__init__(module_id)
        
        self.max_ssid_count = 8
        self.cooldown = '10s'
        self.interval_threshold = 0.25
        self.name = 'flood-module'
        self.msg = 'beacon flooding identified!'

        self.on = (TYPE_MGMT, SUBTYPE_BEACON)
        self.class_ = 'dos'
        self.severity = 'attack'

    def _is_ssid_flood(self, frame: Packet, sm: StatManager, ctx: dict) -> dict|None:
        """ Check's whether an adversary is not flooding the medium with
        bogus SSID's """
        alert = None
        if sm.ssids.get(ctx['channel']) is None:
            return alert

        if len(sm.ssids[ctx['channel']]) > self.max_ssid_count:
            alert = context.alert_base(self, frame, ctx['source'], ctx['frame_number'])

        return alert

    def _is_beacon_flood(self, frame: Packet, sm: StatManager, ctx: dict) -> dict|None:
        """ Check's whether beacon intervals and sequence numbers match. """
        ap_adr  = str(frame.addr2)
        ap_info = sm.aps.get(ap_adr)
        
        if ap_info is None:
            return None

        last_num  = ap_info['last_num']
        last_time = ap_info['last_time']

        interval = frame.time - last_time
        
        raise_alert = False
        alert = context.alert_base(self, frame, ctx['source'], ctx['frame_number']) # TODO Alert
        
        if interval > self.interval_threshold:
            # Todo alert
            alert['reason'].append('irregular beacon interval')
            alert['interval'] = {}
            alert['interval']['expected'] = ap_info['expected_interval']
            alert['interval']['detected'] = interval
            alert['interval']['acceptable'] = self.interval_threshold
            raise_alert = True

        if last_num < frame.SC:
            alert['reason'].append('unexpected sequence number')
            alert['seqnum_last'] = last_num
            alert['seqnum_curr'] = frame.SC
            raise_alert = True

        return alert if raise_alert else None

    def _on_frame(self, frame: Packet, sm: StatManager, ctx: dict) -> list:
        
        alerts = []
        if not (frame.type == 0 and frame.subtype == 8):
            return alerts
        
        ctx['channel'] = context.get_channel(frame)
    
        alert = self._is_ssid_flood(frame, sm, ctx)
        
        if alert is not None:
            alerts.append(alert)

        alert = self._is_beacon_flood(frame, sm, ctx)
        if alert is not None:
            alerts.append(alert)
        
        return alerts

    def create_alert(self, frame: Packet, sm: StatManager, source: str, fidx: int|None) -> dict:
        alert = context.alert_base(self, frame, source, fidx)
        return alert


