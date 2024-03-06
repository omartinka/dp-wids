import utils.context as ctx
from scapy.all import RadioTap

def get_subtype_from_string(val):
    if val == 'beacon':
        return 0, 8
    elif val == 'probe-resp':
        return 0, 5
    elif val == 'assoc-req':
        return 0, 0
    elif val == 'assoc-resp':
        return 0, 1
    elif val == 'reassoc-req':
        return 0, 2
    elif val == 'reassoc-resp':
        return 0, 3
    elif val == 'auth':
        return 0, 0x0b
    elif val == 'deauth':
        return 0, 0x0c
    elif val == 'data':
        return 1, 0
    elif val == 'eapol':
        return 1, 0x08
    elif val == 'deassoc':
        return 0, 0xc
    else:
        print(f"[error] unknown subtype string: {val}")
        return None

def get_config_macs(key):
    is_neg = key[0] == '!'
    mac = key.lstrip('!')
    if mac == '$home':
        return ctx.home_mac + ['ff:ff:ff:ff:ff:ff'], is_neg

    return [key, 'ff:ff:ff:ff:ff:ff'], is_neg

def get_config_ssids(key_):
    if isinstance(key_, list):
        # TODO
        key_list = key_
        for key in key_list:
            pass
    
    else:
        # TODO handle ssids that start with `!` by parsing `\!`
        is_neg = key_[0] == '!'
        key = key_.lstrip('!')

        if key == '$home':
            return [ctx.home], is_neg
        else:
            return [key], is_neg

def get_channel(frame):
    freq = frame.getlayer(RadioTap).ChannelFrequency
    if freq is None:
        return 2447 # TODO TOTO JE KKTINA
    else:
        return get_channel_for_freq(freq)

def get_channel_for_freq(frequency):
    channel = 0
    if frequency < 5000:
        channel = (frequency - 2412) // 5 + 1
    else:
        channel = (frequency - 5180) // 20 + 36
    
    return int(channel)
