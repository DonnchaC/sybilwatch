import logging

handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter(fmt="%(asctime)s [%(levelname)s]: "
                                           "%(message)s"))

logger = logging.getLogger('sybil')
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)


def get_logger():
    """
    Returns a logger.
    """
    return logger
