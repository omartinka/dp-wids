
"""

Krack attack: Vulnerable wireless driver's allow an attacker to
              replay parts of 4-way EAPOL handshake, reinstalling the keys
              and leaking information.

Detection:    Monitor the order of EAPOL handshakes, alert if reinstallment
              Attack is only possible with an evil-twin MITM attack on different channel,
              so additional alert is generated if such attack was recently detected
"""
import modules.base
import utils.context as context

from utils.config import config
from utils.attributes import State
from utils.const import *

from scapy.all import EAPOL, EAPOL_KEY, Packet
from managers.context_manager import context_manager as cm

class KrackModule(modules.base.BaseModule):

    def __init__(self, module_id: int):
        super().__init__(module_id)

        self.cooldown = '0s'
        self.name = 'krack-module'
        self.msg = 'krack attack detected'
        self.class_ = 'data_leak'
        self.severity = 'attack'

        self.on = [(context.TYPE_MGMT, None), (context.TYPE_DATA, None)]

    def _krackable(self, frame: Packet) -> bool:
        """ returns true if packet can be krackabe """
        return True

    def _detect_krack(self, frame: Packet, cm, ctx: dict) -> dict|None:

        alert = context.alert_base(self, frame, ctx['source'], ctx['frame_number'])
        
        """
        if src is AP on bad channel and MSG 3 transmitted - ATTACK FOR SURE

        if src is AP on any channel and MSG 3 is transmitted when already on EAPOL3 state - ATK
        """

        if frame.addr2 in config.home.macs():

            if not frame.haslayer(EAPOL_KEY):
                return None
            
            _attack = False
            eapol_key = frame[EAPOL_KEY]
            keynum = eapol_key.guess_key_number()
            
            if keynum == 3:
                alert['reason'] = []

                client_state = cm.state(frame.addr1, frame.addr2)
                if client_state.state in [State.eapol_3, State.eapol_4]:
                    _attack = True
                    alert['indicators']['client_state'] = str(client_state.state)
                    alert['reason'].append('Retransmission of message 3')
                    
                    if client_state.cipher != 0:
                        alert['rsn_cipher_suite'] = RSN[client_state.cipher]

                chan = alert['channel']
                if chan not in config.home.channels():
                    _attack = True
                    alert['indicators']['channel'] = chan
                    alert['reason'].append('Multi channel MITM')
                
                # TODO XXX Severity - get encryption method used in the key handshake
                # from authentication frames

            if _attack:
                return alert

        return None

    def _on_frame(self, frame: Packet, sm, ctx: dict) -> list:
        alerts = []
        alert = self._detect_krack(frame, cm, ctx)
        if alert is not None:
            alerts.append(alert)

        return alerts
