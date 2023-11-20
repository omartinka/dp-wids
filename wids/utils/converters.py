
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
