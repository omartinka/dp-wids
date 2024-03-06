
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


