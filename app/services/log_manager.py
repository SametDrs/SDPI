"""Dönen dosya destekli ve bellek içi halka tamponlu uygulama log yöneticisi.

Güvenlik kuralı: Paket yükleri (payload) veya SNI alan adları hiçbir zaman loglanmaz.
"""

from __future__ import annotations

import logging
import threading
from collections import deque
from logging.handlers import RotatingFileHandler
from pathlib import Path

from app.constants import LOG_FILE, LOGS_DIR, VALID_LOG_LEVELS


class RingBufferLogHandler(logging.Handler):
    """Tanılama ekranında son log satırlarını göstermek için iş parçacığı güvenli halka tampon."""

    def __init__(self, maxlen: int = 300) -> None:
        super().__init__()
        self._lock = threading.Lock()
        self._records: deque[str] = deque(maxlen=maxlen)

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
            with self._lock:
                self._records.append(msg)
        except Exception:
            self.handleError(record)

    def snapshot(self) -> list[str]:
        with self._lock:
            return list(self._records)

    def clear(self) -> None:
        with self._lock:
            self._records.clear()


class LogManager:
    """Uygulama genelinde Python `logging` yapılandırmasını yönetir."""

    def __init__(self, log_file: Path = LOG_FILE, level: str = "INFO") -> None:
        self._log_file = log_file
        self._ring_handler = RingBufferLogHandler(maxlen=300)
        self._logger = logging.getLogger("sdpi")
        self._configured = False
        self.configure(level=level)

    def configure(self, level: str = "INFO") -> None:
        normalized = level.upper() if level.upper() in VALID_LOG_LEVELS else "INFO"
        numeric_level = getattr(logging, normalized, logging.INFO)
        self._logger.setLevel(numeric_level)
        self._logger.propagate = False

        if self._configured:
            for handler in self._logger.handlers:
                handler.setLevel(numeric_level)
            return

        formatter = logging.Formatter(
            fmt="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        self._ring_handler.setFormatter(formatter)
        self._ring_handler.setLevel(numeric_level)
        self._logger.addHandler(self._ring_handler)

        try:
            LOGS_DIR.mkdir(parents=True, exist_ok=True)
            self._log_file.parent.mkdir(parents=True, exist_ok=True)
            file_handler = RotatingFileHandler(
                self._log_file,
                maxBytes=2 * 1024 * 1024,
                backupCount=3,
                encoding="utf-8",
            )
            file_handler.setFormatter(formatter)
            file_handler.setLevel(numeric_level)
            self._logger.addHandler(file_handler)
        except OSError as exc:
            self._logger.warning("Log dosyasi acilamadi (%s): %s", self._log_file, exc)

        self._configured = True

    @property
    def logger(self) -> logging.Logger:
        return self._logger

    @property
    def log_file(self) -> Path:
        return self._log_file

    def recent_lines(self) -> list[str]:
        return self._ring_handler.snapshot()

    def clear_recent(self) -> None:
        self._ring_handler.clear()
