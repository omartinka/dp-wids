from utils.converters import *
from utils.getters import *
import json

MODE_TRACE = 0
MODE_REALTIME = 1
DUP_CHECK = 100
QUEUE_LEN = 10000

mode = MODE_REALTIME

home = "mojessid"
home_mac = ["00:00:ca:fe:ba:be"]
# non-overlapping !
home_channels = []

rule_file = '../data/rules/basic.json'
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
