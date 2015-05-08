"""
This module provides a set of functions for reading Tor consensus documents.
"""

import stem
import stem.descriptor

import log

logger = log.get_logger()


def get_descriptors(controller):
    """
    Load all relay descriptors from the cached-descriptors
    """
    cached_descriptors = {}
    try:
        for desc in controller.get_server_descriptors():
            cached_descriptors[desc.fingerprint] = desc
    except IOError as err:
        logger.critical("Could not load server descriptors from Tor: %s" %
                        err)
        raise
    return cached_descriptors


def get_consensus(controller):
    """
    Load all relay descriptors in the consensus
    """
    cached_consensus = {}
    try:
        for desc in controller.get_network_statuses():
            cached_consensus[desc.fingerprint] = desc
    except IOError as err:
        logger.critical("Could not load consensus from Tor: %s" % err)
        raise
    return cached_consensus


def get_hsdirs(cached_consensus):
    """
    Get fingerprints for relays in the consensus with the HSDir flag.
    """
    hsdirs = []

    # Get relay descriptors with the HSDir flag
    for _, desc in cached_consensus.items():
        if stem.Flag.HSDIR in desc.flags:
            hsdirs.append(desc.fingerprint)

    return hsdirs
