from utils.converters import *
from utils.getters import *
from utils.alerts import *
from utils.attributes import *
from utils.config import config

import json

TYPE_MGMT = 0
TYPE_CTRL = 1
TYPE_DATA = 2 

SUBTYPE_BEACON = STYPE_BEACON = 8
SUBTYPE_DEAUTH = STYPE_DEAUTH = 0xc
SUBTYPE_DISASS = STYPE_DISASS = 0xa 

MODE_NONE     = 0
MODE_TRACE    = 1
MODE_REALTIME = 2

DUP_CHECK = 100
QUEUE_LEN = 10000

SOCK_TIMEOUT = sock_timeout = 0.2

try_decrypt_kr00k = False
kr00k_alert_unknown = False

mode = MODE_REALTIME

home = "mojessid"
home_mac = ["00:00:ca:fe:ba:be"]
# non-overlapping !
home_channels = []

rule_file = None
trace_file = None

elastic_addr = None
elastic_port = 80
output_file = None
verbose_logging = False

learning_for = 10

def load_config_from_file(file):
    with open(file) as f:
        data = json.load(f)
        
        global rule_file, home, home_mac, home_channels
        rule_file = data['rule_file']
        home = data['home']
        home_mac = data['home_mac']
        home_channels = data['home_channels']
