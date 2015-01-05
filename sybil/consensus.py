import os

import stem
import stem.descriptor

import log

logger = log.get_logger()


def get_descriptors(data_dir):
    """
    Load all relay descriptors from the cached-descriptors
    """
    cached_descriptors = {}
    cached_descriptors_path = os.path.join(data_dir, "cached-descriptors")
    try:
        for desc in stem.descriptor.parse_file(cached_descriptors_path):
            cached_descriptors[desc.fingerprint] = desc
    except IOError as err:
        logger.critical("File \"%s\" could not be read: %s" %
                        (cached_descriptors_path, err))
        raise
    return cached_descriptors


def get_consensus(data_dir):
    """
    Load all relay descriptors in the consensus
    """
    cached_consensus = {}
    cached_consensus_path = os.path.join(data_dir, "cached-consensus")
    try:
        for desc in stem.descriptor.parse_file(cached_consensus_path):
            cached_consensus[desc.fingerprint] = desc
    except IOError as err:
        logger.critical("File \"%s\" could not be read: %s" %
                        (cached_consensus_path, err))
        raise
    return cached_consensus


def get_hsdirs(cached_consensus):
    """
    Get fingerprints for relays in the consensus with the HSDir flag.
    """
    hsdirs = []

    # Get relay descriptors with the HSDir flag
    for fpr, desc in cached_consensus.iteritems():
        if stem.Flag.HSDIR in desc.flags:
            hsdirs.append(desc.fingerprint)

    return hsdirs
