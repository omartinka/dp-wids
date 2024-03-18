# TODO XXX pip install keyboard
import keyboard
import managers

import enum

class Signal(enum.Enum):
    prevent_learn_network = 0
    prevent_learn_device  = 1


class SignalManager:
    signals: set[str] == None

    def __init__(self):
        self.signals = set()
        keyboard.on_press(on_s_press)

    def on_s_press(self, evt):
        if event.name == 's':
            managagers.context_manager.summary()

    def get_signals(self):
        _tmp = self.signals[:]
        self.signals = set()
        return _tmp

signal_manager = SignalManager
