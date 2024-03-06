import modules.base
import utils.context as context

from managers.stat_manager import StatManager
from scapy.all import Packet

class DeauthModule(modules.base.BaseModule):

    def __init__(self, module_id: int):
        super().__init__(module_id)


    def _on_frame(self, frame: Packet, sm: StatManager, ctx: dict) -> list:
        alerts = []
        
        # We only care about deauth frames
        if not (frame.type == context.TYPE_MGMT and frame.subtype == context.STYPE_DEAUTH):
            return alerts


        return []

