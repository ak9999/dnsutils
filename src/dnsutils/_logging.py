"""Centralized logging configuration for dnsutils."""

import logging
import sys


def configure_logging(level: int = logging.INFO) -> None:
    """Configure logging for the dnsutils package.

    Args:
        level: Logging level (default: INFO).
    """
    # Get the root logger for dnsutils
    logger = logging.getLogger("dnsutils")

    # Only configure if not already configured (check for direct handlers)
    if logger.handlers:
        return

    logger.setLevel(level)

    # Create console handler
    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(level)

    # Create formatter with timestamp, module, function name, and level
    formatter = logging.Formatter(
        fmt="%(asctime)s - %(name)s:%(funcName)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(formatter)

    # Add handler to logger
    logger.addHandler(handler)
