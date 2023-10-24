import utils.context as ctx
from managers.elastic import elastic

import json
import time

alert_manager = None

class AlertManager:
    def __init__(self):
        self.write_to = None
        self.cooldowns = {}

    def init(self):
        if ctx.output_file:
            self.write_to = open(ctx.output_file, 'a')
    
    def __parse_log_level(self, level: str) -> str:
        """ 
        info: matches info rule
        warning: attack could have happened, but we are not sure, need more info from 3rd party sensors
        alert: attack happened for sure
        """
        if level not in ['info', 'warning', 'alert']:
            level = 'info'
        return level

    def __parse_log_type(self, ltype: str) -> str:
        return ltype

    def __do_send(self, rule) -> bool:
        """ checks whether to send an alert.
        some alerts have a cooldown field to not DoS ourselves
        """
        last = self.cooldowns.get(rule.id)
        this = int(time.time())

        if last == None:
            self.cooldowns[rule.id] = this
            return True
        
        if last + rule.cooldown > this:
            return False

        self.cooldowns[rule.id] = this
        return True

    def alert(self, rule, data, level='alert'):
        if not self.__do_send(rule):
            return

        if ctx.elastic_addr:
            elastic.log(level, data)
        
        if ctx.output_file and self.write_to:
            self.write_to.write(json.dumps(data) + '\n')
        
        if ctx.verbose_logging:
            print(json.dumps(data))

    def close(self):
        self.write_to.close()

    @classmethod
    def get(cls):
        return alert_manager

alert_manager = AlertManager()
def get():
    return alert_manager
