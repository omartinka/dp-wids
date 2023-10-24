import socket
import threading
import signal

from analyze.input import input_stream

class DataReceiver:
    def __init__(self):
        self.on = True

        self.host = '0.0.0.0'
        self.port = 7777
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(1)
        self.sock.bind((self.host, self.port))

        self.sock.listen(5)
    
        self.cthread = None
        self.shutdown_flag = threading.Event()
    
    def run(self):
        print(f'listening on {self.host}:{self.port}')
        while self.on:
            try:
                csock, caddr = self.sock.accept()
                if self.cthread is not None:
                    self.shutdown_flag.set()
                    self.cthread.join()
                
                self.shutdown_flag = threading.Event()
                self.cthread = threading.Thread(target=self._handle, args=(csock,))
                self.cthread.start()
            except socket.timeout:
                pass

    def _stop(self):
        return self.shutdown_flag.is_set()

    def _handle(self, client_sock):
        while not self._stop():
            try:
                data = b''
                while not self._stop() and len(data) < 2:
                    chunk = client_sock.recv(2 - len(data))
                    if not chunk: 
                        raise ValueError('?')
                    data += chunk

                length = int.from_bytes(data, byteorder='big')
                data = b''
                while not self._stop() and len(data) < length:
                    chunk = client_sock.recv(length - len(data))
                    if not chunk:
                        raise ValueError('??')
                    data += chunk
                
                input_stream.process(data)

            except Exception as e:
                print(e)
                break
    
    def stop(self):
        self.on = False
        if self.cthread:
            self.shutdown_flag.set()
            self.cthread.join()

data_receiver = DataReceiver()

def signal_handler(sig, frame):
    if sig == signal.SIGINT:
        data_receiver.stop()

signal.signal(signal.SIGINT, signal_handler)
