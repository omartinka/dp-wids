import socket
import threading
import signal

from analyze.input import input_stream
from managers import log_manager

import utils.context as ctx
from utils.config import config

class DataReceiver:
    def __init__(self):
        self.host = '0.0.0.0'
        self.port = 7777

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(ctx.sock_timeout)
        self.sock.bind((self.host, self.port))

        self.sock.listen(5)

        self.cthread = None
        self.shutdown_flag = threading.Event()

        # We allow multiple frame sources
        # should NOT happen because there is no duplication check
        # but we allow it yay

        self.client_threads = {}

    def run(self):
        self.shutdown_flag = threading.Event()

        while True:
            try:
                csock, caddr = self.sock.accept()

                if not config.aggregator.allow_any:

                    # aggregator ip is not in whitelist
                    if caddr[0] not in config.sensor.allowed:
                        log_manager.warn(f"sensor connection attempt from unallowed ip {caddr[0]}")
                        csock.close()
                        return

                client_key = caddr[0] + ':' + str(caddr[1])

                # If attempt to connect from the same ip twice then wtf do i do even
                if client_key in self.client_threads:
                    return

                client_thread = threading.Thread(target=self._handle, args=(csock,))
                self.client_threads[client_key] = client_thread

                client_thread.start()

            # Do nothing if timeout occurs - this just makes CTRL+C work
            except socket.timeout:
                pass

            # Kill the analyzer if CTRL+C
            except KeyboardInterrupt:
                # Set shutdown signal
                self.shutdown_flag.set()

                # Wait for all client threads to end (aggregator processes)
                for client_key in self.client_threads:
                    self.client_threads[client_key].join()

                # Exit the infinity loop
                return

    def _handle(self, client_sock):
        client_sock.settimeout(config.sock_timeout)

        while not self.shutdown_flag.is_set():
            try:
                data = b''

                # Get the length of incoming frame
                while not self.shutdown_flag.is_set() and len(data) < 2:
                    chunk = client_sock.recv(2 - len(data))
                    if not chunk:
                        raise ValueError('?')
                    data += chunk

                length = int.from_bytes(data, byteorder='big')

                # Get frame with size of length gotten previously
                data = b''
                while not self.shutdown_flag.is_set() and len(data) < 32 + length:
                    chunk = client_sock.recv(32 + length - len(data))

                    if not chunk:
                        raise ValueError('conn broken probs.')

                    data += chunk

                # Sensor ID
                sensor_id = data[0:32].decode('utf-8', errors='ignore').strip('\0')

                # Process the assembled frame
                input_stream.process(data[32:], sensor=sensor_id)

            # No data in a while - ok
            except socket.timeout:
                pass

            # Something broke
            except Exception as e:
                log_manager.error(e)
                break


data_receiver = DataReceiver()
