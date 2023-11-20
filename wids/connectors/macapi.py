import requests

API_ADDR = 'https://api.macvendors.com'
SPECIAL = {
    'ff:ff:ff:ff:ff:ff': "BROADCAST"
}
CACHE = {}

def get_vendor(mac_addr: str) -> str:
    # in case it is scapy-object
    mac_addr = str(mac_addr)

    if mac_addr in SPECIAL:
        return SPECIAL[mac_addr]
    
    if mac_addr in CACHE:
        return CACHE[mac_addr]
    
    resp = requests.get(f'{API_ADDR}/{mac_addr}')
    if resp.status_code != 200:
        return "unknown mac vendor"
    
    vendor = resp.content.decode('utf-8', errors='ignore')
    
    CACHE[mac_addr] = vendor

    return vendor
