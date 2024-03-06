
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
