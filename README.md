# Защищённый E2EE чат (курсовой проект)

Реализация защищённого чата с сквозным шифрованием по протоколу Signal:
- ECDH на Curve25519, X3DH, Double Ratchet, AES-256-GCM, HKDF-SHA256.
- Серверная часть: KDS (Key Distribution Server) и MessageServer (FastAPI WebSocket).
- Клиент: CLI с криптографией на стороне пользователя.
- Хранение ключей: тома Docker для `/app/keys`, логи `/app/logs`.
- Безопасность: PBKDF2 для паролей, replay protection, ротация SPK.

## Развёртывание

1. Установите Docker и docker-compose.
2. Клонируйте репозиторий и перейдите в папку `secure-chat`.
3. Соберите и запустите сервисы:
```bash
docker-compose up -d --build
```


## Запуск клиента

Установите зависимости:

```bash
pip install -r requirements.txt
```
Генерация ключей и регистрация:

```bash
python client/cli.py register
```
Отправка сообщения:

```bash
python client/cli.py send -r username -m "secret text"
```
Приём сообщений в реальном времени:

```bash
python client/cli.py listen
```

Тестирование
```bash
pytest tests/ -v
```
Включает тесты X3DH, Double Ratchet, AES-GCM по векторам NIST.