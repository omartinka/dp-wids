from managers.alert_manager import alert_manager
from managers.rule_manager import rule_parser

def init():
    rule_parser.init()
    alert_manager.init()
