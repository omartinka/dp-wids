import utils.context as ctx
import managers.log_manager as lm

from scapy.all import *

class Indicator:
    def __init__(self, indicator: dict):
        self._attr_radiotap = {}
        self._attr_dot11    = {}
        self._attr_deauth   = {}
        self._attr_stats    = {}    

        self._hits   = 0
        self._checks = 0

        self._parse(indicator)

    def _get_layer(self, key: str) -> str|None:
        if key in ['radiotap', 'dot11', 'deauth']:
            return key

        return None

    def _get_attr(self, name: str) -> dict:
        if name == 'radiotap':
            return self._attr_radiotap
        elif name == 'dot11':
            return self._attr_dot11
        elif name == 'deauth':
            return self.attr_death
        else:
            lm.warn(f'error while parsing indicator: unknown/unimplemented layer {name}')
            return {}

    def _parse_val(key, value):
        pass

    def _parse(self, indicator: dict) -> None:
        for key in indicator:
            layer = self._get_layer(key)
            if layer is not None:
                self._parse(indicator[layer])
            else:
                collection = self._get_attr(layer)

                if key in collection:
                    to_add = self._parse_val(key, indicator[key])
                    collection[key] += to_add

                else:
                    collection[key] = self._parse_val(key, indicator[key])

    def __str__(self):
        _str = f""" Indicator: 
            _radiotap: {self._attr_radiotap}
            _dot11: {self._attr_dot11}
            _deauth: {self.attr_deauth}
            total checks: {self._checks}, total hits: {self._hits}
        """
        return _str

    def _apply_one(self, layer, attr: str, layer_str: str, collection: dict) -> bool
        """ Return true if attribute matches in the frame
        """
        if layer is None:
            lm.warn(f'error while applying indicator: unknown layer {}')

        # Get the scapy name of attribute so we know what to compare with
        _attr = ctx.translate_attribute(layer_str, attr)

        if _attr is None:
            lm.warn(f'error while applying indicator: unknown attribute {attr}')
            return False
        
        pattr = getattr(layer, _attr)

        if pattr is None:
            lm.warn(f'error while applying indicator: attribute {_attr} not present')
            return False
        
        if op is None:
            lm.warn(f'error while applying indicator: unknown operation in attribute {_attr}')
            return False
        
        if op is None:
            lm.warn(f'error while applying indicator: unknown negation in attribute {_attr}')
            return False

        res = False

        # Get the value of attribute to compare with value from packet
        # attr == key, collection[key] == value
        data, op, neg = ctx.get_attribute_arr(layer_str, attr, collection[attr])

        if op == '>':
            res = _attr > pattr
        elif op == '<':
            res = _attr < pattr
        elif op == '=':
            res = _attr == pattr
        elif op == '>=':
            res = _attr >= pattr
        elif op == '<=':
            res = _attr <= pattr
        else:
            lm.warn(f'error while applying indicator: unknown operation {op}, idk wtf happened')
            return False

        if neg:
            res = not res

        return res

    def apply(self, frame: Packet) -> bool:
        self._checks += 1
        
        for attr in self._attr_radiotap:
            layer = frame.getlayer(RadioTap)
            ok = self._apply_one(layer, attr, 'radiotap', self._attr_radiotap)
            
            # If any indicator does not match, the rule does not match
            if not ok:
                return False

        for attr in self._attr_dot11:
            pass

        for attr in self._attr_deauth:
            pass
        
        for attr in self._attr_stats:
            pass

        # All indicators are true
        return True
