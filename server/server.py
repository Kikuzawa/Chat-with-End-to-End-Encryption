"""
MessageServer – основной WebSocket сервер (стр. 33).
"""
import asyncio
import json
import hashlib
import os
import sys
import base64
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from contextlib import asynccontextmanager
import httpx

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import redis.asyncio as aioredis
except ImportError:
    import aioredis

from config import REDIS_URL, KDS_API_KEY, KDS_INTERNAL_PORT
from log_utils import get_file_logger, SEP, SEP2

_log = get_file_logger("server", "server.log")

redis_pool = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global redis_pool
    _log.info(SEP2)
    _log.info("[SERVER/INIT] ▶ MessageServer запускается")
    _log.info(f"[SERVER/INIT]   Redis URL: {REDIS_URL}")
    try:
        redis_pool = await aioredis.from_url(REDIS_URL, decode_responses=True)
        await redis_pool.ping()
        _log.info("[SERVER/INIT] ✓ Подключение к Redis установлено")
        print(f"MessageServer: Подключен к Redis ({REDIS_URL})")
    except Exception as e:
        _log.error(f"[SERVER/INIT] ✗ Ошибка подключения к Redis: {e}")
        print(f"MessageServer: Ошибка подключения к Redis: {e}")
        raise
    yield
    _log.info("[SERVER/SHUTDOWN] Завершение работы — закрываем соединения")
    for ws in connections.values():
        try:
            await ws.close()
        except:
            pass
    if redis_pool:
        await redis_pool.close()
    _log.info("[SERVER/SHUTDOWN] ✓ Завершено")

app = FastAPI(title="MessageServer", lifespan=lifespan)
connections: dict[str, WebSocket] = {}

def pbkdf2_hash(password: str, salt: bytes = None) -> tuple:
    if salt is None:
        salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return key, salt

async def kds_upload_bundle(username: str, bundle: dict):
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"http://kds:{KDS_INTERNAL_PORT}/users/{username}/bundle",
                json=bundle,
                headers={"X-API-Key": KDS_API_KEY},
                timeout=10.0
            )
            resp.raise_for_status()
            _log.info(f"[SERVER/KDS]   POST /users/{username}/bundle → {resp.status_code} OK")
            print(f"KDS: Bundle uploaded for {username}")
    except Exception as e:
        _log.error(f"[SERVER/KDS] ✗ Ошибка загрузки bundle для {username}: {e}")
        print(f"KDS upload error: {e}")
        raise

async def kds_get_bundle(username: str) -> dict:
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"http://kds:{KDS_INTERNAL_PORT}/users/{username}/bundle",
                headers={"X-API-Key": KDS_API_KEY},
                timeout=10.0
            )
            resp.raise_for_status()
            data = resp.json()
            _log.info(f"[SERVER/KDS]   GET /users/{username}/bundle → {resp.status_code} OK")
            return data
    except Exception as e:
        _log.error(f"[SERVER/KDS] ✗ Ошибка получения bundle для {username}: {e}")
        print(f"KDS get bundle error: {e}")
        raise

async def store_message(recipient: str, message: dict):
    await redis_pool.rpush(f"queue:{recipient}", json.dumps(message))
    _log.info(f"[SERVER/QUEUE]   Сообщение сохранено в Redis queue:{recipient}")

async def deliver_offline_messages(username: str, websocket: WebSocket):
    key = f"queue:{username}"
    count = 0
    while True:
        msg_json = await redis_pool.lpop(key)
        if msg_json is None:
            break
        msg = json.loads(msg_json)
        await websocket.send_json(msg)
        count += 1
    if count:
        _log.info(f"[SERVER/QUEUE]   Доставлено {count} оффлайн сообщений для '{username}'")

@app.get("/health")
async def health():
    return {"status": "ok"}

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    _log.info(SEP)
    _log.info("[SERVER/WS] ▶ Новое WebSocket подключение")
    await ws.accept()
    _log.info("[SERVER/WS]   Соединение принято")
    username = None
    auth_token = None

    try:
        while True:
            data = await ws.receive_text()
            msg = json.loads(data)
            msg_type = msg.get("type")

            if msg_type == "register":
                username = msg.get("username")
                _log.info(SEP)
                _log.info(f"[SERVER/REGISTER] ▶ Регистрация: '{username}'")
                password = msg.get("password")
                if not username or not password:
                    _log.warning("[SERVER/REGISTER] ✗ Пустые поля username/password")
                    await ws.send_json({"type": "error", "message": "Username and password required"})
                    continue
                exists = await redis_pool.hexists(f"user:{username}", "password_hash")
                if exists:
                    _log.warning(f"[SERVER/REGISTER] ✗ Пользователь '{username}' уже существует")
                    await ws.send_json({"type": "error", "message": "User already exists"})
                    continue
                key, salt = pbkdf2_hash(password)
                _log.info(f"[SERVER/REGISTER]   PBKDF2-SHA256, 100000 итераций")
                _log.info(f"[SERVER/REGISTER]   salt = {salt.hex()}")
                _log.info(f"[SERVER/REGISTER]   hash = {key[:8].hex()}...")
                await redis_pool.hset(f"user:{username}", mapping={
                    "password_hash": base64.b64encode(key).decode(),
                    "salt": base64.b64encode(salt).decode()
                })
                _log.info(f"[SERVER/REGISTER]   Данные сохранены в Redis: user:{username}")
                bundle = msg.get("bundle")
                if bundle:
                    _log.info(f"[SERVER/REGISTER]   Загрузка bundle в KDS...")
                    try:
                        await kds_upload_bundle(username, bundle)
                        _log.info(f"[SERVER/REGISTER]   Bundle успешно загружен в KDS")
                    except Exception as e:
                        _log.error(f"[SERVER/REGISTER] ✗ Ошибка загрузки bundle: {e}")
                        print(f"Bundle upload error: {e}")
                _log.info(f"[SERVER/REGISTER] ✓ ГОТОВО  Пользователь '{username}' зарегистрирован")
                print(f"User {username} registered successfully")
                await ws.send_json({"type": "register", "status": "ok"})

            elif msg_type == "login":
                username = msg.get("username")
                _log.info(SEP)
                _log.info(f"[SERVER/LOGIN] ▶ Аутентификация: '{username}'")
                password = msg.get("password")
                if not username or not password:
                    _log.warning("[SERVER/LOGIN] ✗ Пустые поля")
                    await ws.send_json({"type": "error", "message": "Invalid credentials"})
                    continue
                user_data = await redis_pool.hgetall(f"user:{username}")
                if not user_data:
                    _log.warning(f"[SERVER/LOGIN] ✗ Пользователь '{username}' не найден")
                    await ws.send_json({"type": "error", "message": "Invalid credentials"})
                    continue
                stored_hash = base64.b64decode(user_data["password_hash"])
                salt = base64.b64decode(user_data["salt"])
                test_key, _ = pbkdf2_hash(password, salt)
                if test_key != stored_hash:
                    _log.warning(f"[SERVER/LOGIN] ✗ Неверный пароль для '{username}'")
                    await ws.send_json({"type": "error", "message": "Invalid credentials"})
                    continue
                token = os.urandom(32).hex()
                await redis_pool.setex(f"token:{token}", 3600, username)
                _log.info(f"[SERVER/LOGIN]   Токен выдан (TTL 3600с): {token[:16]}...")
                auth_token = token
                connections[username] = ws
                _log.info(f"[SERVER/LOGIN]   Активных соединений: {len(connections)}")
                _log.info(f"[SERVER/LOGIN] ✓ ГОТОВО  Пользователь '{username}' вошёл")
                print(f"User {username} logged in")
                await ws.send_json({"type": "login", "status": "ok", "token": token})
                await deliver_offline_messages(username, ws)

            elif msg_type == "update_bundle":
                _log.info(SEP)
                _log.info(f"[SERVER/UPDATE_BUNDLE] ▶ Обновление bundle для '{username}'")
                if not auth_token:
                    _log.warning("[SERVER/UPDATE_BUNDLE] ✗ Не аутентифицирован")
                    await ws.send_json({"type": "error", "message": "Not authenticated"})
                    continue
                bundle = msg.get("bundle")
                if not bundle:
                    _log.warning("[SERVER/UPDATE_BUNDLE] ✗ Bundle отсутствует в запросе")
                    await ws.send_json({"type": "error", "message": "Bundle required"})
                    continue
                try:
                    await kds_upload_bundle(username, bundle)
                    _log.info(f"[SERVER/UPDATE_BUNDLE] ✓ Bundle обновлён в KDS для '{username}'")
                    print(f"Bundle updated for {username}")
                    await ws.send_json({"type": "update_bundle", "status": "ok"})
                except Exception as e:
                    _log.error(f"[SERVER/UPDATE_BUNDLE] ✗ Ошибка: {e}")
                    await ws.send_json({"type": "error", "message": f"Bundle update failed: {e}"})

            elif msg_type == "get_bundle":
                target = msg.get("username")
                _log.info(SEP)
                _log.info(f"[SERVER/GET_BUNDLE] ▶ Запрос bundle: '{username}' запрашивает ключи '{target}'")
                if not auth_token:
                    _log.warning("[SERVER/GET_BUNDLE] ✗ Не аутентифицирован")
                    await ws.send_json({"type": "error", "message": "Not authenticated"})
                    continue
                if not target:
                    _log.warning("[SERVER/GET_BUNDLE] ✗ Не указан target username")
                    await ws.send_json({"type": "error", "message": "Username required"})
                    continue
                try:
                    bundle = await kds_get_bundle(target)
                    _log.info(f"[SERVER/GET_BUNDLE] ✓ Bundle получен из KDS для '{target}'")
                    await ws.send_json({"type": "bundle", "username": target, "bundle": bundle})
                except Exception as e:
                    _log.error(f"[SERVER/GET_BUNDLE] ✗ Bundle не найден для '{target}': {e}")
                    await ws.send_json({"type": "error", "message": f"User bundle not found: {str(e)}"})

            elif msg_type == "send":
                if not auth_token:
                    await ws.send_json({"type": "error", "message": "Not authenticated"})
                    continue
                recipient = msg.get("recipient")
                message_payload = msg.get("message")
                _log.info(SEP)
                _log.info(f"[SERVER/SEND] ▶ Маршрутизация: '{username}' → '{recipient}'")
                _log.info(f"[SERVER/SEND]   Тип payload: {message_payload.get('type') if message_payload else 'нет'}")
                if not recipient or not message_payload:
                    _log.warning("[SERVER/SEND] ✗ Отсутствует recipient или message")
                    await ws.send_json({"type": "error", "message": "Recipient and message required"})
                    continue

                if recipient in connections:
                    _log.info(f"[SERVER/SEND]   Получатель '{recipient}' онлайн — прямая доставка")
                    await connections[recipient].send_json({
                        "type": "message",
                        "sender": username,
                        "data": message_payload
                    })
                    _log.info(f"[SERVER/SEND] ✓ Доставлено напрямую: {username} → {recipient}")
                    print(f"Message sent from {username} to online user {recipient}")
                else:
                    _log.info(f"[SERVER/SEND]   Получатель '{recipient}' оффлайн — сохраняем в очередь")
                    await store_message(recipient, {
                        "type": "message",
                        "sender": username,
                        "data": message_payload
                    })
                    _log.info(f"[SERVER/SEND] ✓ Сохранено в очереди Redis для '{recipient}'")
                    print(f"Message from {username} to {recipient} stored offline")
                await ws.send_json({"type": "ack", "status": "sent"})

            elif msg_type == "logout":
                _log.info(SEP)
                _log.info(f"[SERVER/LOGOUT] ▶ Пользователь '{username}' выходит")
                print(f"User {username} logging out")
                break

            else:
                _log.warning(f"[SERVER/WS] ✗ Неизвестный тип сообщения: {msg_type}")
                await ws.send_json({"type": "error", "message": f"Unknown message type: {msg_type}"})

    except WebSocketDisconnect:
        _log.info(f"[SERVER/WS]   Клиент '{username}' отключился (WebSocketDisconnect)")
        print(f"Client {username} disconnected")
    except Exception as e:
        _log.error(f"[SERVER/WS] ✗ Ошибка WebSocket для '{username}': {e}")
        print(f"WebSocket error for {username}: {e}")
    finally:
        if username and username in connections:
            del connections[username]
            _log.info(f"[SERVER/WS]   '{username}' удалён из активных соединений. Осталось: {len(connections)}")
            print(f"Removed {username} from connections")
        if auth_token:
            await redis_pool.delete(f"token:{auth_token}")
            _log.info(f"[SERVER/WS]   Токен удалён из Redis")
