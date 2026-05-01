# 🔐 Защищённый E2EE чат

Курсовой проект: чат с end-to-end шифрованием на Python.

## Криптография
- **Key Agreement:** X3DH (Extended Triple Diffie-Hellman)
- **Ratchet:** Double Ratchet Algorithm
- **Шифрование:** AES-256-GCM (IV: 12 байт, tag: 16 байт)
- **KDF:** HKDF-SHA256
- **Кривые:** Curve25519 (X25519 + Ed25519)


## Быстрый старт

### Docker (рекомендуется)
```bash
docker-compose up -d --build
```

# Терминал 1: KDS
python -m uvicorn server.kds:app --host 0.0.0.0 --port 8001

# Терминал 2: Message Server  
python -m uvicorn server.server:app --host 0.0.0.0 --port 8000

# Терминал 3: Регистрация
python client/cli.py register -u alice -p alice123
python client/cli.py register -u bob -p bob123

# Терминал 4: Чат
python client/cli.py chat -u alice -p alice123 -r bob
python client/cli.py chat -u bob -p bob123 -r alice

Команды
Команда	Описание
register -u USER -p PASS	Регистрация нового пользователя
chat -u USER -p PASS -r RECIPIENT	Интерактивный чат
send -u USER -p PASS -r RECIPIENT -m MSG	Отправить сообщение
listen -u USER -p PASS	Ожидание входящих сообщений

Тестирование
bash
pytest tests/ -v


Безопасность
Пароли хешируются PBKDF2-SHA256 (100 000 итераций)

TLS 1.3 для WebSocket (WSS)

Forward secrecy через Double Ratchet

Replay protection через порядковые номера сообщений

Ротация SPK каждые 7 дней