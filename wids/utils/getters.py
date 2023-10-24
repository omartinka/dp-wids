import utils.context as ctx

def get_subtype_from_string(val):
    if val == 'beacon':
        return 0, 8
    elif val == 'probe_resp':
        return 0, 5

def get_config_macs(key):

    is_neg = key[0] == '!'
    mac = key.lstrip('!')
    
    if mac == '$home':
        return ctx.home_mac, is_neg

    return [key], is_neg

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
