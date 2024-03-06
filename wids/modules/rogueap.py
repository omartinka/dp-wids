import modules.base
import utils.context as context

from utils.const import * 
from utils.config import config

from managers.stat_manager import StatManager
from scapy.all import Packet

class RogueApModule(modules.base.BaseModule):
    """ Module for detecting MitM attempts. """
    def __init__(self, module_id: int):
        super().__init__(module_id)
        self.rssi_threshold = 4
        self.cooldown = '10s'
        self.name = 'rogue-ap-module'
        self.msg = 'a home network is being spoofed'
        self.class_ = 'impersonation'
        self.severity = 'attack'

    def _mitm_advertising(self, frame: Packet, sm: StatManager, ctx: dict) -> dict|None:
        if not ((frame.type, frame.subtype) == (TYPE_MGMT, SUBTYPE_BEACON)):
            return None
        
        alert = None
        raise_alert = False
        
        # Not my ssid - i do not care.
        ssid = str(frame.info.decode('utf-8', errors='ignore'))
        if ssid not in config.home:
            return None
        
        alert = context.alert_base(self, frame, ctx['source'], ctx['frame_number'])

        # Home ssid is being advertised for unknown mac
        for home_ssid in config.home:

            # make sure we compare correct configured home network
            if not home_ssid == ssid:
                continue

            expected_mac = config.home[home_ssid].mac
            if str(frame.addr2).lower() not in [x.lower() for x in expected_mac]:
                alert['reason'].append('unknown source address for home ap')
                alert['mac_expected'] = [x.lower() for x in expected_mac]
                alert['mac_recv'] = str(frame.addr2).lower()
                raise_alert = True


        # An AP with my ssid is advertising itself on unknown channel
        for home_ssid in config.home:
            if home_ssid != str(ssid):
                continue

            expected_chan = config.home[home_ssid].channels
            if ctx['channel'] not in expected_chan:
                alert['reason'].append('home network advertised on unexpected channel')
                alert['indicators']['channels'] = {}
                alert['indicators']['channels']['expected'] = expected_chan
                alert['indicators']['channels']['detected'] = ctx['channel']
                raise_alert = True

        # RSSI is fluctuating - possible same channel attack
        ap_info = sm.aps.get(str(frame.addr2))
         
        if ap_info:
            fluctuation = abs(ap_info['expected_rssi'] - frame.dBm_AntSignal)
            if fluctuation > self.rssi_threshold:
                alert['reason'].append('rssi fluctiation')
                alert['rssi_expected'] = ap_info['expected_rssi']
                alert['rssi_measured'] = frame.dBm_AntSignal
                alert['rssi_threshold'] = self.rssi_threshold
                raise_alert = True

        # Add SSID of network being spoofed
        if raise_alert:
            alert['spoofed_ssid'] = str(ssid)

        return alert if raise_alert else None

    def _on_frame(self, frame: Packet, sm: StatManager, ctx: dict) -> list:
        alerts = []
        alert = self._mitm_advertising(frame, sm, ctx)
        if alert is not None:
            alerts.append(alert)

        return alerts
