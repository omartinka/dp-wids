# ** USED **

from utils.config import config
import managers.log_manager as lm

from connectors import connectors

import json
import time
import datetime
import socket
import threading

alert_manager = None

class AlertDstTCP:
    def __init__(self, name):
        """ For sending data through TCP """
        self.name = name
        self.sock_fd = None
        self.on = False
        self.addr = ()
        
    def init(self, addr, port):
        port = int(port)
        self.addr = (addr, port)
        self.on = True
 
    def connect(self):
        self.sock_fd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock_fd.connect(self.addr)
    
    def log(self, level, data):
        if not self.on:
            lm.error(f'tcp alert destination {name} not connected!')
            return
        self.connect()
        self.sock_fd.sendall(json.dumps(data).encode()) 
        self.sock_fd.close()

class AlertManager:
    def __init__(self):
        self.write_to = None
        self.cooldowns = {}
        self.tcp_nodes = []
        
        self.alert_threads = []

    def init(self):
        self.tcp_nodes = []
        self.cooldowns = {}
        if self.write_to is not None:
            self.write_to.close()
        self.write_to = None

        if len(config.remote) > 0:
            # Go through all remote alert destinations and create a client for each
            for node in config.remote:
                try:
                    addr, port = node
                    client = AlertDstTCP(f'TCP:{addr}')
                    client.init(addr, port)
                    self.tcp_nodes.append(client)
                except:
                    lm.error(f'could not connect to alert destination: {addr}:{port}.')
                    continue

        if config.output_file:
            self.write_to = open(config.output_file, 'a')
    
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
        if rule.cooldown is None:
            return True

        last = self.cooldowns.get(rule.id)
        this = int(time.time())

        if last == None:
            self.cooldowns[rule.id] = this
            return True
        
        if last + rule.cooldown > this:
            return False

        self.cooldowns[rule.id] = this
        return True

    def _alert(self, data, level='alert'):
        
        # resolve connector attributes
        if '_to_resolve' in data:
            for item in data['_to_resolve']:
                key = item['key']
                val = item['val']
                resolver = item['resolver']
                try:
                    connector = connectors[resolver['connector']]
                    data[key] = getattr(connector, resolver['func'])(val)
                except Exception as e:
                    lm.warn(f'[WARN] Failed to resolve connector: (cls) `{resolver["connector"]}` (fun) `{resolver["func"]}`')
        
        # Clean up
        del data['_to_resolve']

        # fix up timestamp
        try:
            t = datetime.datetime.fromtimestamp(float(data['timestamp']))
            data['timestamp'] = str(t)
        except:
            ts = data['timestamp']
            lm.warn(f'[WARN] could not parse timestamp: [{ts}]')

        for node in self.tcp_nodes:
            try:
                node.log(level, data)
            except:
                lm.warn(f'connection to {node.name} broken!')
        if config.output_file and self.write_to:
            self.write_to.write(json.dumps(data) + '\n')
        
        if config.verbose:
            print(json.dumps(data))

    def alert(self, data, level='alert'):
        """ Generates an alert. 
        This is done in a separate thread to not block the WIDS in case of
        an alert with slow resolver elements.
        """
        t = threading.Thread(target=self._alert, args=(data, level))
        self.alert_threads.append(t)
        t.start()

    def close(self):
        self.write_to.close()
        for _t in self.alert_threads:
            if _t.is_alive():
                _t.join()

    @classmethod
    def get(cls):
        return alert_manager

alert_manager = AlertManager()
def get():
    return alert_manager
