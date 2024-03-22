from managers.context_manager import context_manager
from utils.config import config

import datetime

def get_802_11_type_as_str(packet):
    return "beacon"

def is_overlapping(ch1: int, ch2: int) -> bool:
    
    # 2.4ghz
    if ch1 < 20 and ch2 < 20:
        return abs(ch2 - ch1) <= 5

    # 5ghz
    elif ch1 < 70 and ch2 < 70:
        return abs(ch1 - ch2) <= 3

    # 6ghz/bogus
    else:
        return True

def parse_cooldown(cd):
    if cd.endswith('ns'):
        return int(cd[:-2], 10) / 60 / 60
    if cd.endswith('ms'):
        return int(cd[:-2], 10) / 60
    if cd.endswith('s'):
        return int(cd[:-1], 10)
    if cd.endswith('m'):
        return int(cd[:-1], 10) * 60
    if cd.endswith('h'):
        return int(cd[:-1], 10) * 60 * 60

def parse_op_time(data):
    # [>,<,<=,>=,==,!=]
    # <int>
    # [s,ms,ns,m,h,d]
    return _,_,_

def flatten_json(y):
    out = {}

    def flatten(x, name=''):
        if type(x) is dict:
            for a in x:
                flatten(x[a], name=a)
        elif type(x) is list:
            i = 0
            for a in x:
                flatten(a, name='')
                i += 1
        else:
            if name in out:
                out[name].append(x)
            else:
                out[name] = [x]

    flatten(y)
    return out

def parse_expr(attr, frame=None, sensor=None):
    def _normalize(x):
        if isinstance(x, str):
            return f"\"{x}\""
        return x

    repl_ = {}
    for var in attr.expr.split(' '):
        if var[0] == '$':
            var_ = var[1:]
            if var_ == 'val':
                repl_[var] = getattr(frame, attr.attr)
                continue
            if var_ == 'rssi':
                repl_[var] = context_manager.rssi(frame.addr2, sensor).last
                continue
            if var_ == 'home':
                repl_[var] = config.home.macs()
                continue
            if var_ in dict(config.vars):
                repl_[var] = config.vars[var_]
                continue

    res = attr.expr
    for x in repl_:
        res = res.replace(x, str(_normalize(repl_[x])))

    return res

def match_time(expr: str, val):
    def _normalize(x):
        if isinstance(x, str):
            return f"\"{x}\""
        return x
    
    repl_ = {}
    for var in expr.split(' '):
        if var[0] == '$':
            var_ = var[1:]
            if var_ == 'val':
                repl_[var] = val
                continue
            if var_ in dict(config.vars):
                repl_[var] = config.vars[var_]
                continue
            if var_ in dict(config.vars.time):
                repl_[var] = config.vars.time[var_]
                continue
    res = expr
    for x in repl_:
        res = res.replace(x, str(_normalize(repl_[x])))
    return res

def as_var(attr, frame=None, sensor=None):
    if attr[0] != '$':
        return attr
    
    premade_vars = {
        'home': config.home.macs(),
        'rssi': managers.context_manager.get().rssi(frame.addr2, sensor).last
    }

    attr = attr[1:]
    if attr in premade_vars:
        return premade_vars[attr]
    var = getattr(config.vars, attr)
    
    return str(var)
