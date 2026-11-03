"""Structured logging. Never logs passwords or secrets."""
from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler

from app.config import LOG_DIR, ensure_dirs


def setup_logging(level: int = logging.INFO) -> logging.Logger:
    ensure_dirs()
    logger = logging.getLogger("bruta_x")
    if logger.handlers:
        return logger
    logger.setLevel(level)
    fmt = logging.Formatter(
        "%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    fh = RotatingFileHandler(LOG_DIR / "bruta_x.log", maxBytes=1_000_000, backupCount=3)
    fh.setFormatter(fmt)
    fh.setLevel(level)
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    sh.setLevel(level)
    logger.addHandler(fh)
    logger.addHandler(sh)
    return logger
