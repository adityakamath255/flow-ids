import logging
from collections.abc import Iterable
from math import sqrt
from typing import NamedTuple


class Statistics(NamedTuple):
    total: float
    maximum: float
    minimum: float
    mean: float
    standard_deviation: float


def get_logger(debug: bool = False) -> logging.Logger:
    logger = logging.getLogger("cicflowmeter")
    if not logger.hasHandlers():
        logging.basicConfig()
    logger.setLevel(logging.DEBUG if debug else logging.WARNING)
    return logger


def get_statistics(
    values: Iterable[float],
    scale: float = 1.0,
) -> Statistics:
    samples = tuple(float(value) for value in values)
    if not samples:
        return Statistics(0, 0, 0, 0, 0)

    total = sum(samples)
    mean = total / len(samples)
    variance = sum((value - mean) ** 2 for value in samples) / len(samples)
    return Statistics(
        total * scale,
        max(samples) * scale,
        min(samples) * scale,
        mean * scale,
        sqrt(variance) * scale,
    )
