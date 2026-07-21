import logging
import uuid
from itertools import islice, zip_longest

import numpy


def get_logger(debug=False):
    logger = logging.getLogger("cicflowmeter")
    if not logger.hasHandlers():
        logging.basicConfig()
    logger.setLevel(logging.DEBUG if debug else logging.WARNING)
    return logger


def grouper(iterable, n, max_groups=0, fillvalue=None):
    """Collect data into fixed-length chunks or blocks"""

    if max_groups > 0:
        iterable = islice(iterable, max_groups * n)

    args = [iter(iterable)] * n
    return zip_longest(*args, fillvalue=fillvalue)


def random_string():
    return uuid.uuid4().hex[:6].upper().replace("0", "X").replace("O", "Y")


def get_statistics(alist: list):
    """Get summary statistics of a list"""
    alist = [float(x) for x in alist]

    if not alist:
        return {"total": 0, "max": 0, "min": 0, "mean": 0, "std": 0}

    return {
        "total": sum(alist),
        "max": max(alist),
        "min": min(alist),
        "mean": numpy.mean(alist),
        "std": numpy.sqrt(numpy.var(alist)),
    }
