"""Logging utilities for Attack Surface Mapper."""
import logging
import sys
from colorama import Fore, Style, init

# Initialize colorama for cross-platform color support
init(autoreset=True)


class ColoredFormatter(logging.Formatter):
    """Custom formatter with color support."""

    COLORS = {
        'DEBUG': Fore.CYAN,
        'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.RED + Style.BRIGHT,
    }

    def format(self, record):
        """Format log record with colors."""
        levelname = record.levelname
        if levelname in self.COLORS:
            record.levelname = f"{self.COLORS[levelname]}{levelname}{Style.RESET_ALL}"
        return super().format(record)


def setup_logger(name='attack_surface_mapper', verbose=False):
    """
    Set up a logger with colored output.

    Args:
        name: Logger name
        verbose: If True, set log level to DEBUG, otherwise INFO

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    # Remove existing handlers to avoid duplicates
    logger.handlers.clear()

    # Console handler with colored output
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG if verbose else logging.INFO)

    formatter = ColoredFormatter(
        '%(levelname)s - %(message)s'
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger
