from utils.config import config
from utils.const import *
import time

from managers.receiver import data_receiver
from managers.filestream import file_stream
from managers.context_manager import context_manager

class Wids:
    def __init__(self):
        self._start = time.time()
        self._end   = None

    def _run_trace(self):
        file = config.trace_file
        file_stream.process(file)        
        return 0

    def _run_realtime(self):
        data_receiver.run()
        return 0

    def run(self):
        ret = -1

        if config.mode == MODE_TRACE:
            ret = self._run_trace()

        if config.mode == MODE_REALTIME:
            ret = self._run_realtime()
       
        context_manager.summary()

        return ret

wids = Wids()
