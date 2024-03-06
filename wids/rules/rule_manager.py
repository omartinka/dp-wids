import utils.context as ctx
import managers.log_manager as lm

class Indicator:
    pass

class Rule:
    def __init__(self, data):
        self.id = data['id']
        self.on = data['on'] 
        self.name = data['id']
        self.class_ = data['class']
        self.type_ = data['type']
        self.msg = data['msg']
        self.cooldown = self.__parse_cooldown(data['cooldown']) if 'cooldown' in data else None
        self.indicators = self._parse_indicators(data['indicators'])
        self._last_cooldown = None

    def _generate_alert(self, packet, indicators, sensor, frame_number=None):
        return ctx.alert_base(self, packet, sensor, frame_number)

    def _parse_indicators(self, indicators):
        _indicators = []
        for i in indicators:
            _indicators.append(Indicator(i))
        return _indicators

    def _applicable(self, packet):
        """ returns true if rule is applicable on the packet
        """

        # first check frame types
        for t_ in self.on:
            t, st = ctx.get_subtype_from_string(t_)
            if t == packet.type and st == packet.subtype:
                return True

        return False


    def apply(self, packet, sensor, frame_number=None):
        if not self._applicable(packet):
            return

        indicators = []
        for indicator in self.indicators:
            if indicator.apply(packet):
                indicators.append(indicator)

        if len(indicators):
            # Generate alert...
            alert = self._generate_alert(packet, indicators, sensor, frame_number=frame_number)
            return alert
        
        return None


class RuleManager:
    def __init__(self):
        pass

    def init(self):
        self._rules = []

        if ctx.rule_file is None:
            lm.warn('no rule file specified.')
        
        try:
            with open(ctx.rule_file) as f:
                data = json.load(f)
                if data.get('rules') is None:
                    lm.warn('rule file does not contain key `rules`')
                    return

                for rule in data['rules']:
                    try:
                        parsed_rule = Rule(rule)
                        self._rules.append(parsed_rule)
                    except:
                        lm.warn(f'cannot parse rule: {rule}')
                        continue

        except:
            lm.error('rule file does not exist or cannot be read!')

    # 
    def apply_rules(self, data):
        for rule in self._rules:
            rule.apply(data)


rule_manager = RuleManager()
