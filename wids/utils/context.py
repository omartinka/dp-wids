from utils.converters import *
from utils.getters import *

MODE_TRACE = 0
MODE_REALTIME = 1
DUP_CHECK = 100
QUEUE_LEN = 10000

config = {
    "home": {
        "ssid": "domecek",
        "channels": [],
        "mac": ""
    }

}

mode = MODE_REALTIME
home = "mojessid"
home_mac = ["00:00:ca:fe:ba:be"]
rule_file = '../data/rules/basic.json'
trace_file = None

elastic_addr = None
elastic_port = 80
output_file = None
verbose_logging = False
