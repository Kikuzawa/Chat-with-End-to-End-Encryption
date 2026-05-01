"""
Глобальные константы проекта
"""
import os

# Криптографические параметры
CURVE = "curve25519"
HKDF_HASH = "SHA256"
AES_KEY_SIZE = 32
IV_SIZE = 12
TAG_SIZE = 16
PREKEY_POOL_SIZE = 100
SPK_ROTATION_DAYS = 7

# Сетевые настройки
KDS_INTERNAL_PORT = 8001
SERVER_PORT = 8000
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379")
KDS_API_KEY = os.getenv("KDS_API_KEY", "internal-secret-key")

# Хранение ключей
KEY_DIR = os.getenv("KEY_DIR", "/app/keys")
LOG_DIR = os.getenv("LOG_DIR", "/app/logs")