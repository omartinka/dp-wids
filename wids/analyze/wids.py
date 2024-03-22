from utils.config import config
from utils.const import *

import time
import threading

from managers.receiver import data_receiver
from managers.filestream import file_stream
from managers.context_manager import context_manager

class Wids:
    thread_signal: threading.Thread = None
    thread_wids: threading.Thread = None
    shutdown_flag: threading.Event = None


    def __init__(self):
        self._start = time.time()
        self._end   = None
        self.shutdown_flag = threading.Event()

    def _run_trace(self):
        try:
            file = config.trace_file
            file_stream.process(file)        
            return 0
        except KeyboardInterrupt:
            self.shutdown_flag.set()

    def _run_realtime(self):
        data_receiver.run()
        return 0
    
    def _handle_signal(self):
        
        def _help(parent=None):
            print('Help: \'h\' for this help')
            print('      \'s\' for summary')
            print('      \'d\' for device list')
            print('      \'n\' for network list')
            print('      \'c\' for running config')
            print('      \'q\' for exit')
            print('')

        if not config.interactive:
            return

        _help(self)

        while not self.shutdown_flag.is_set():
            try:
                action = input('-> ')
                time.sleep(0.1)
                
                if action == 'h':
                    _help(self)

                elif action == 's':
                    context_manager.info_summary()
                
                elif action == 'c':
                    context_manager.info_config()

                elif action == 'd':
                    context_manager.info_devices()

                elif action == 'n':
                    context_manager.info_networks()

                if action == 'q':
                    self.kill()

            except KeyboardInterrupt:
                self.kill()

    def kill(self):
        if config.mode == MODE_TRACE:
            file_stream.kill()
        
        if config.mode == MODE_REALTIME:
            data_receiver.kill()

        self.shutdown_flag.set()
                
    def run(self):
        ret = -1

        if config.mode == MODE_TRACE:
            self.thread_wids = threading.Thread(target=self._run_trace)

        elif config.mode == MODE_REALTIME:
            self.thread_wids = threading.Thread(target=self._run_realtime)
        
        else:
            return -1

        self.thread_signal = threading.Thread(target=self._handle_signal)

        self.thread_wids.start()
        self.thread_signal.start()

        self.thread_wids.join()
        self.thread_signal.join()

        return ret

wids = Wids()
