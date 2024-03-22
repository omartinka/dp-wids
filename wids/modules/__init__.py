import modules.flood
import modules.rogueap
import modules.kr00k
import modules.krack

from scapy.all import Packet
from utils.config import config

import utils.context as ctx
import connectors.macapi

NEXTID = 0

def get_id():
    global NEXTID
    NEXTID += 1
    return NEXTID

module_map = {
    'flood': flood.FloodModule,
    'rogueap': rogueap.RogueApModule,
    'kr00k': kr00k.KrookModule,
    'krack': krack.KrackModule    
}

def init_modules(to_load):
    global NEXTID, modules
    NEXTID = 0
    modules_ = []
    for name in to_load:
        if name not in module_map:
            print(f'[error] module {name} does not exist!')
        else:
            modules_.append(module_map[name](get_id()))
    modules = modules_

modules = {
    'flood': flood.FloodModule(get_id()),
    'rogueap': rogueap.RogueApModule(get_id()),
    'kr00k': kr00k.KrookModule(get_id()),
    'krack': krack.KrackModule(get_id())
}

available = [mm for mm in module_map]

def enabled():
    return [modules[x] for x in config.modules]
