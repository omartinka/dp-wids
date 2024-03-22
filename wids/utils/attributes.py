from scapy.all import *
from typing import List, Tuple
from utils.const import *

import enum
from utils.config import config

_ATTRS = {
    "radiotap": {
        "rssi": "db"
    }
}

_OPS = ['>=', '<=', '=', '>', '<']

def _parse_special(layer: str, attr: list):
    # get val from config if starts with `$` and therefore is a variable
    # if attr not in '$home'
    pass

def translate_attribute(layer, attr):
    """ Gets the scapy name of attribute """
    neg = True if attr[0] == '!' else False
    op = None
    data = None

    attr = attr[1:]
    
    for op_ in _OPS:
        if attr.startswith(op_):
            op = op_
            attr = attr[len(op_):]
            break
    else:
        return None, None, None

    if attr[0] == '$':
        data = _parse_special(layer, attr)
    else:
        data = attrs[layer][attr]

    return data, op, neg


class State(enum.Enum):
    unknown  =  0
    asso_req =  1
    asso_rsp =  2
    auth_req =  3
    auth_rsp =  4
    eapol_1  =  5
    eapol_2  =  6
    eapol_3  =  7
    eapol_4  =  8
    deauth   =  9
    disass   = 10

    def __str__(self):
        if self == State.eapol_3:
            return "eapol-message-3"
        if self == State.eapol_4:
            return "eapol-message-4"
        return self.name
    

def is_frame(frame: Packet, s_types: List[Tuple[int,int]]) -> Tuple[bool, Tuple[int,int]]:
    """ Checks if frame is of given type """
    for s_type in s_types:
        if (s_type[0] == None or frame.type == s_type[0]) and (frame.subtype == s_type[1] or s_type[1] == None):
            return True, (s_type[0], s_type[1])
    return False, None

def state_for_type(type_: Tuple[int,int]) -> State:
    """ Returns state for given type """
    if type_ == F_ASSOREQ:
        return State.asso_req
    if type_ == F_ASSORESP:
        return State.asso_rsp
    if type_ == F_REASSOREQ:
        return State.asso_req
    if type_ == F_REASSORESP:
        return State.asso_rsp
    if type_ == F_AUTH:
        return State.auth_req
    if type_ == F_EAPOL:
        return State.eapol_1
    if type_ == F_DEAUTH:
        return State.deauth
    if type_ == F_DISASS:
        return State.disass
    return State.unknown

def get_eapol_state(frame: Packet) -> State:
    """ Returns state for given EAPOL frame """
    if frame.haslayer(EAPOL_KEY):
        msg_key = frame[EAPOL_KEY].guess_key_number()
        if msg_key == 1 or msg_key == 0:
            return State.eapol_1
        if msg_key == 2:
            return State.eapol_2
        if msg_key == 3:
            return State.eapol_3
        if msg_key == 4:
            return State.eapol_4

    return State.unknown
