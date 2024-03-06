""" Creates a profile file from a trace based on input config """
from utils.config import config


class Profiler:    
    # Needs to be created per-sensor

    # Map of each home mac rssi values relative to sensor
    rssi: dict[str,int] = {}
    network_cnt: int = 0
    

    def __init__(self):
        
        # 
        tf = config.trace_file

        pass
