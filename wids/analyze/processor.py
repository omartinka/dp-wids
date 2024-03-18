from managers import rule_manager, alert_manager, context_manager
from modules import modules
import utils.context as context

class FrameProcessor:
    def __init__(self):
        self.rm = rule_manager.get()
        self.am = alert_manager.get()
        self.cm = context_manager.get()

    def process(self, frame, source=None, frame_number=None):

        # # if wids not in learning mode, check for intrusions
        if not self.cm.learning:
        #  """ rules temporarly disabled

        #     for rule in self.rm.rules():
        #         alert =rule.apply(frame, sensor=source, frame_number=frame_number)
        #         if alert is not None:
        #             self.am.alert(alert)
        #
            for module in modules:
                alerts = module.on_frame(frame, self.cm, {"source": source, "frame_number": frame_number, "channel": context.get_channel(frame)})
                if len(alerts) is not None:
                    for alert in alerts:
                        self.am.alert(alert)                     

        # self.sm.on_frame(frame, source, frame_number)
        self.cm.on_frame(frame, source, frame_number)
frame_processor = FrameProcessor()

def get():
    return frame_processor

