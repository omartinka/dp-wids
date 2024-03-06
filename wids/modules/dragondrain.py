"""
Module for detection the "dragondrain" attack on WPA3.

- attacker sends commit messages to AP
    - high resource usage (cpu, power)
    - prevents AP from sending commit messages to other nodes

"""

import modules.base


class DragonDrainModule(modules.base.BaseModule):
    
    def __init__(self, module_id: int):
        super().__init__(module_id)


    def _detect_krack(self, frame: Packet, sm: StatManager, ctx: dict) -> dict|None:

        return None


    def _on_frame(self, frame: Packet, sm: StatManager, ctx: dict) -> list:
        alerts = []
        alert = self._detect_krack(frame, sm, ctx)
        
        if alert is not None:
            alerts.append(alert)
        
        return alerts

