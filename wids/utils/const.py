from enum import Enum
from scapy.all import *

class D11Type(Enum):
    pass    

# Frame types
TYPE_MGMT = MGMT = 0
TYPE_CTRL = CTRL = 1
TYPE_DATA = DATA = 2 

# Frame subtypes
SUBTYPE_BEACON = STYPE_BEACON = BEACON = 8
SUBTYPE_DEAUTH = STYPE_DEAUTH = DEAUTH = 0xc
SUBTYPE_DISASS = STYPE_DISASS = DISASS = 0xa 
SUBTYPE_ASSOCREQ = STYPE_ASSOCREQ = ASSOREQ = 0

F_ASSOREQ    = (0, 0)
F_ASSORESP   = (0, 1)
F_REASSOREQ  = (0, 2)
F_REASSORESP = (0, 3)
F_PROBEREQ   = (0, 4)
F_PROBERESP  = (0, 5)
F_BEACON     = (0, 8)
F_DISASS     = (0, 0xa)
F_AUTH       = (0, 0xb)
F_DEAUTH     = (0, 0xc)
F_ACTION     = (0, 0xd)
F_EAPOL      = (2, None)

# Wids behavior mode
MODE_NONE     = 0
MODE_TRACE    = 1
MODE_REALTIME = 2

# Rule string to layer map
RULE_LAYER = {
    "ether": Ether,
    "dot11": Dot11,
    "beacon": Dot11Beacon,
    "assocreq": Dot11AssoReq,
    "assoresp": Dot11AssoResp,
    "reassoreq": Dot11ReassoReq,
    "reassoresp": Dot11ReassoResp,
    "probereq": Dot11ProbeReq,
    "proberesp": Dot11ProbeResp,
    "disass": Dot11Disas,
    "auth": Dot11Auth,
    "deauth": Dot11Deauth,
    "action": Dot11Action,
    "eapol": EAPOL,
    "eapol-key": EAPOL_KEY
}

RSN = {
    0x00: "None",
    0x01: "WEP-40",
    0x02: "TKIP",
    0x03: "OCB",
    0x04: "CCMP-128",
    0x05: "WEP-104",
    0x06: "BIP-CMAC-128",
    0x07: "Group addressed traffic not allowed",
    0x08: "GCMP-128",
    0x09: "GCMP-256",
    0x0A: "CCMP-256",
    0x0B: "BIP-GMAC-128",
    0x0C: "BIP-GMAC-256",
    0x0D: "BIP-CMAC-256"
}
