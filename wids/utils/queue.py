from collections import deque

class Queue(deque):
    def __init__(self, _maxlen, _callback):
       super().__init__(maxlen=_maxlen)

       self.callback = _callback

    def append(self, item):

        # if the queue is full, call callback function before popping the first element
        if len(self) == self.maxlen:
            if self.callback is not None:
                self.callback(self[0])

        super().append(item)

