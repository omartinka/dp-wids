import logging

logger = logging.getLogger('wids')

logging.basicConfig(
    level=logging.DEBUG,
    format='[%(asctime)s][%(levelname)s]: %(message)s'
)

def debug(msg):
    logger.debug(msg)

def info(msg):
    logger.info(msg)

def warn(msg):
    logger.warning(msg)

def error(msg):
    logger.error(msg)

def critical(msg):
    logger.critical(msg)
