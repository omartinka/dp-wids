from managers.alert_manager import alert_manager
from managers.rule_manager import rule_parser
from managers.signal_manager import signal_manager

def init():
    rule_parser.init()
    alert_manager.init()
