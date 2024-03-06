from scapy.all import Packet
from managers.stat_manager import StatManager

from managers import log_manager
import connectors.macapi
import utils.context as ctx
import time

class BaseModule:
    def __init__(self, module_id: int):
        """ Define static variables
        """
        # Do not modify these
        self.id = module_id 
        self.type_ = 'module'

        # Modify these !
        self.cooldown = "10s" # Xms|s|m|h
        self.class_ = "info" # dos|impersonation|dataleak|...

        self.name = "Base Module" 
        self.msg = "Base message not modified!"

        # do not touch
        self._last_cooldown = None
        self.on = []

    # Load configuration from parsed yaml config
    def load_config(self, _config: dict):
        for key in _config:
            if getattr(self, key, None) is not None:
                setattr(self, key, _config[key])
            else:
                log_manager.warn(f"Module {self.name} does not have a `{key}` attribute")

    def _helper_func(self, frame: Packet, sm:StatManager, myvar: str) -> None:
        # Create as many helper functions as you want
        pass

    def _do_check(self, frame):
        if self._last_cooldown is None:
            self._last_cooldown = frame.time
            return True
        
        if self._last_cooldown + ctx.parse_cooldown(self.cooldown) < frame.time:
            self._last_cooldown = frame.time
            return True
        
        return False

    def applicable(self, frame: Packet):
        ok = False
        if len(self.on) == 0:
            return True
        
        if isinstance(self.on, list):
            for pair in self.on:
                t_, s_ = pair
                if frame.type == t_:
                    if s_ == None or (s_ != None and frame.subtype == s_):
                        return True
            return False
        else:
            t_, s_ = self.on
            if frame.type != t_:
                return False
            if s_ is not None and frame.type != s_:
                return False
            ok = True
        return ok

    def on_frame(self, frame: Packet, sm: StatManager, ctx: dict) -> list:
        """ The whole IDS logic for your module goes here...
        """

        if not self.applicable(frame):
            return []

        alerts = self._on_frame(frame, sm, ctx)
        if len(alerts) and self._do_check(frame):
            return alerts

        return []

    def _on_frame(self, frame, sm, ctx):
        return []


    def create_alert(self, frame: Packet, sm: StatManager, source: str, fidx: int|None) -> dict:
        """ Generates the body of the alert sent to SIEM. Do not modify its base, just add 
        information relevant to this module.

        @frame:  the frame that is being analyzed
        @sm:     stat manager instance, in case it is necessary to log data from it
        @source: where the frame came from, usually sensor id or trace file
        @fidx:   index of frame in source if read from a trace file
        
        Returns:
            @alert: dict with the generated alert fields
        """

        alert = ctx.alert_base(self, frame, source, fidx)

        # Modify as you wish
        # alert['indicator'] = some_val

        return alert
