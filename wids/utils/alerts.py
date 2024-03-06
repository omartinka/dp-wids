from scapy.all import Packet
import connectors.macapi
import utils.getters

def alert_base(module: object, frame: Packet, source: str, frame_number: int|None) -> dict:
    alert = {
        module.type_ + "_id": module.id,
        "timestamp": frame.time,
        "class": module.class_,
        "type": module.type_,
        "msg": module.msg,
        "module": module.name,
        "severity": module.severity,
        "reason": [],
        "indicators": {},
        "channel": utils.getters.get_channel(frame)
    }
    pairs = [
        ('mac_dst', frame.addr1),
        ('mac_src', frame.addr2), 
        ('mac_ap', frame.addr3)
    ]

    for key, val in pairs:
        if val is not None and val != '00:00:00:00:00:00':
            alert[key] = val

    alert['_to_resolve'] = []
    for key, val in pairs:
        if val is not None:
            alert['_to_resolve'].append({
                'key': key + '_vendor', 
                'val': val, 
                'resolver': {
                    'connector': 'macapi',
                    'func': 'get_vendor'}
                })
    
    if source is not None:
        alert['source'] = source

    if frame_number is not None:
        alert['frame_number'] = frame_number

    return alert
