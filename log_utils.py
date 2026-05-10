"""
Общий модуль настройки файлового логирования для всех компонентов.
Каждый компонент пишет в свой файл в LOG_DIR:
  webapp.log   — Flask/SocketIO операции
  crypto.log   — X3DH, Double Ratchet, AES-256-GCM
  server.log   — MessageServer операции
  keymanager.log — генерация и хранение ключей
"""
import logging
import os

_loggers: dict = {}

FMT = "%(asctime)s.%(msecs)03d | %(message)s"
DATE = "%H:%M:%S"


def get_file_logger(name: str, filename: str) -> logging.Logger:
    """Возвращает (создаёт если нет) logger, пишущий в LOG_DIR/filename."""
    if name in _loggers:
        return _loggers[name]

    log_dir = os.getenv("LOG_DIR", "/app/logs")
    os.makedirs(log_dir, exist_ok=True)

    log = logging.getLogger(f"file.{name}")
    log.setLevel(logging.DEBUG)
    log.propagate = False

    if not log.handlers:
        fh = logging.FileHandler(
            os.path.join(log_dir, filename),
            encoding="utf-8",
            mode="a",
        )
        fh.setFormatter(logging.Formatter(FMT, datefmt=DATE))
        fh.setLevel(logging.DEBUG)
        log.addHandler(fh)

    _loggers[name] = log
    return log


def h(data: bytes, n: int = 12) -> str:
    """Показать первые n байт в hex для логов."""
    return data[:n].hex() + ("..." if len(data) > n else "")


def b64s(data: bytes, n: int = 12) -> str:
    """Показать первые n байт в base64 для логов."""
    import base64
    return base64.b64encode(data[:n]).decode() + ("..." if len(data) > n else "")


SEP  = "─" * 72
SEP2 = "═" * 72
