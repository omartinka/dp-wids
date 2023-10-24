import socket
import json

from enum import Enum
import utils.context as ctx

class ElasticClient:

    def __init__(self):
        self.sock_fd = None
        self.on = False
        self.addr = ()
    
    def init(self):
        if ctx.elastic_addr == None:
            return

        addr = ctx.elastic_addr
        port = ctx.elastic_port

        self.addr = (addr, port)
        self.on = True
 
    def connect(self):
        self.sock_fd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock_fd.connect(self.addr)
    
    def log(self, level, data):
        if not self.on:
            print('NOT CONNECTED TO ELASTIC.')
            return
        self.connect()
        self.sock_fd.sendall(json.dumps(data).encode()) 
        self.sock_fd.close()

elastic = ElasticClient()


