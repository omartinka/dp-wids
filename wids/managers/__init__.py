from managers.alert_manager import alert_manager
from managers.elastic import elastic

def init():
    alert_manager.init()
    elastic.init()
