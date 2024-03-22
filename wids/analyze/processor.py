from managers import rule_manager, alert_manager, context_manager
import modules
import utils.context as context

class FrameProcessor:
    def __init__(self):
        self.rm = rule_manager.get()
        self.am = alert_manager.get()
        self.cm = context_manager.get()
        self.modules_enabled = []

    def process(self, frame, source=None, frame_number=None):

        # # if wids not in learning mode, check for intrusions
        if not self.cm.learning:

            # first check all rules
            for rule in self.rm.rules():
                alert = rule.apply(frame, sensor=source, frame_number=frame_number)
                if alert is not None:
                    self.am.alert(alert)
        
            # then check for alerts in modules
            for module_ in self.modules_enabled:
                alerts = module_.on_frame(
                    frame=frame, 
                    cm=self.cm, 
                    ctx={
                        "source": source, 
                        "frame_number": frame_number, 
                        "channel": context.get_channel(frame)
                    }
                )
                if len(alerts) is not None:
                    for alert in alerts:
                        self.am.alert(alert)                     

        # update network state
        self.cm.on_frame(frame, source, frame_number)

frame_processor = FrameProcessor()

def get():
    return frame_processor

def init():
    frame_processor.modules_enabled = modules.enabled()
    print(frame_processor.modules_enabled)
