"""
Kr00k:     after the disconnect of a station node, the frames left in 
           the wireless chip's buffer are still sent, but the encryption keys
           are zeroed out, and therefore the data can be decrypted by anyone
           listening on the wireless medium

Detection: Throw an alert about possible kr00k attack if a data frame is
           detected after a device is deauthenticated. There is no way of knowing 
           whether the attack was successful or not without the knowledge of 
           sta's devices driver or trying to decrypt the intercepted data - we will not do this
"""
import modules.base
import binascii
import utils.context as context

from utils.config import config
from utils.attributes import State

from managers.context_manager import ContextManager, context_manager as cm

from scapy.all import Packet, Dot11CCMP, Dot11
from Cryptodome.Cipher import AES
from re import sub

class KrookModule(modules.base.BaseModule):

    def __init__(self, module_id: int):
        super().__init__(module_id)
        
        self.cooldown = '0s'
        self.name = 'kr00k-module'
        self.msg = 'possible kr00k attack detected!'
        self.class_ = 'data_leak'
        self.severity = 'possible attack'

        self.on = [(context.TYPE_MGMT, None), (context.TYPE_DATA, None)]
        
        self.alert_states = [State.deauth, State.disass]
        if context.kr00k_alert_unknown:
            alert_states.append(None)
            
    def _try_decrypt(self, frame, cm: ContextManager, ctx: dict, alert: dict) -> bool:
        # Decrypt the frame according to r00kie_kr00kie
        # update alert
        data = frame.data[:-8]
        pn0 = "{:02x}".format(frame.PN0)
        pn1 = "{:02x}".format(frame.PN1)
        pn2 = "{:02x}".format(frame.PN2)
        pn3 = "{:02x}".format(frame.PN3)
        pn4 = "{:02x}".format(frame.PN4)
        pn5 = "{:02x}".format(frame.PN5)
        addr2 = sub(':', '', frame.addr2)
        qos = '00'
        nonce = bytes.fromhex(qos) + bytes.fromhex(addr2) + bytes.fromhex(pn5 + pn4 + pn3 + pn2 + pn1 + pn0)
        tk = bytes.fromhex("00000000000000000000000000000000")
        cipher = AES.new(tk, AES.MODE_CCM, nonce, mac_len=8)
        decrypted_data: bytes = cipher.decrypt(data)
        res = decrypted_data.startswith(b'\xaa\xaa\x03')
        if res == True:
            alert['indicators']['nonce'] = binascii.hexlify(nonce).decode('utf-8')
            alert['indicators']['tk'] = "00000000000000000000000000000000"
            alert['indicators']['leaked_data_dec'] = binascii.hexlify(decrypted_data).decode('utf-8')
            alert['severity'] = 'attack'
        return res

    def _detect_kr00k(self, frame: Packet, cm: ContextManager, ctx: dict) -> dict|None:
        src = frame.addr2
        dst = frame.addr1

        if src in ['ff:ff:ff:ff:ff:ff', None]:
            return None

        # not Dot11CCMP, not kr00k, according to the r00kie kr00kie script
        if not frame.haslayer(Dot11CCMP):
            return None

        # AP does not know about the device
        if src in config.home.macs():
            swp_ = src
            src  = dst
            dst  = swp_

        state = cm.state(src, dst)
        if not state:
            return

        state = state.state
        
        # Get state -- if not authenticated, then data possibly leaked
        # TODO - we only check for state for home network 
        if state in self.alert_states:
            if state is None:
                state = 'in unknown state'
            alert = context.alert_base(self, frame, ctx['source'], ctx['frame_number'])
            alert['reason'] = f'detected data frames from a STA node which is {state}.'
            alert['indicators']['client_state'] = state.name if state is not None else 'unknown'
            alert['indicators']['leaked_data_enc'] = binascii.hexlify(frame.data[:-8]).decode('utf-8')
            if True or context.try_decrypt_kr00k:
                r = self._try_decrypt(frame, cm, ctx, alert)
                if r is False:
                    return None
            return alert

        return None

    def  _on_frame(self, frame: Packet, cm: ContextManager, ctx: dict) -> list:
        alerts = []
        alert = self._detect_kr00k(frame, cm, ctx)
        if alert is not None:
            alerts.append(alert)
        
        return alerts
