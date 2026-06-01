"""
VENGAM — Logging configuration (rich-powered)
"""
from __future__ import annotations
import logging
import sys

try:
    from rich.logging import RichHandler
    _RICH = True
except ImportError:
    _RICH = False


def get_logger(name: str = "vengam", verbose: bool = False) -> logging.Logger:
    level = logging.DEBUG if verbose else logging.INFO

    if _RICH:
        logging.basicConfig(
            level=level,
            format="%(message)s",
            datefmt="[%H:%M:%S]",
            handlers=[RichHandler(rich_tracebacks=True, show_path=False)],
        )
    else:
        logging.basicConfig(
            level=level,
            format="%(asctime)s  [%(levelname)s]  %(message)s",
            datefmt="%H:%M:%S",
            stream=sys.stderr,
        )

    return logging.getLogger(name)


# Module-level default logger — re-configure by calling get_logger() with verbose=True
log = get_logger()
