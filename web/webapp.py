"""
Веб-сервер E2EE чата.

Архитектура:
  Browser  <--Socket.IO-->  webapp.py (Flask)  <--WebSocket-->  MessageServer
                                    │
                           Вся криптография (X3DH + Double Ratchet) выполняется
                           здесь, на стороне webapp.py — пароль не хранится
                           после авторизации.

Исправления:
  - asyncio.run() в Flask-обработчиках заменён на выделенный фоновый event loop
    (run_coroutine_threadsafe), что корректно работает с Flask-SocketIO threading mode.
  - Пароль не сохраняется в памяти после логина.
  - Шифрование/расшифрование работает через SessionManager.
"""
import sys
import os
import json
import asyncio
import threading
import logging
import base64

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, render_template, request
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room
import secrets
import websockets

from crypto.keymanager import KeyManager
from crypto.sessionmanager import SessionManager

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
CORS(app)
# threading mode корректно работает с синхронными обработчиками и фоновым asyncio циклом
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

MESSAGE_SERVER_URL = os.getenv("SERVER_URL", "ws://localhost:8000/ws")

# ── Фоновый asyncio event loop ────────────────────────────────────────────────
_bg_loop: asyncio.AbstractEventLoop = None
_bg_thread: threading.Thread = None


def _ensure_bg_loop():
    global _bg_loop, _bg_thread
    if _bg_loop is not None and _bg_loop.is_running():
        return
    _bg_loop = asyncio.new_event_loop()
    _bg_thread = threading.Thread(target=_bg_loop.run_forever, daemon=True, name="ws-loop")
    _bg_thread.start()


def _run_async(coro, timeout: float = 20.0):
    """Выполняет корутину в фоновом event loop и возвращает результат."""
    _ensure_bg_loop()
    future = asyncio.run_coroutine_threadsafe(coro, _bg_loop)
    return future.result(timeout=timeout)


# ── Хранилище (in-memory, для демонстрации) ───────────────────────────────────
user_keys: dict     = {}   # username -> KeyManager
user_ws: dict       = {}   # username -> websockets.WebSocketClientProtocol
user_sessions: dict = {}   # (username, recipient) -> RatchetState
user_sids: dict     = {}   # username -> socket.io sid


# ── Вспомогательные корутины ──────────────────────────────────────────────────

async def _ws_listen(username: str, ws, sid: str):
    """Фоновый приём входящих сообщений от MessageServer для пользователя username."""
    try:
        async for raw in ws:
            data = json.loads(raw)
            if data.get("type") != "message":
                continue
            sender   = data["sender"]
            msg_data = data["data"]
            try:
                text = _decrypt_incoming(username, sender, msg_data)
                socketio.emit('message', {'sender': sender, 'text': text}, room=sid)
            except Exception as e:
                logger.error(f"Decrypt error ({username} ← {sender}): {e}")
                socketio.emit('message',
                              {'sender': sender, 'text': '[Ошибка расшифровки]', 'error': True},
                              room=sid)
    except Exception as e:
        logger.info(f"WS listener ended for {username}: {e}")


def _decrypt_incoming(username: str, sender: str, msg_data: dict) -> str:
    """Расшифровывает входящее зашифрованное сообщение от sender к username."""
    if username not in user_keys:
        raise ValueError("Ключи пользователя не найдены")

    km = user_keys[username]
    session_key = (username, sender)

    if session_key not in user_sessions:
        if msg_data.get("type") != "prekey":
            raise ValueError("Ожидается prekey-сообщение для новой сессии")
        state = SessionManager.receive_session(
            km.ik_x25519_priv, km.ik_x25519_pub,
            km.spk_priv, km.spk_pub,
            {},
            base64.b64decode(msg_data["ik_a_pub"]),
            base64.b64decode(msg_data["ek_a_pub"]),
            None
        )
        user_sessions[session_key] = state

    state = user_sessions[session_key]
    ciphertext = base64.b64decode(msg_data["ciphertext"])
    return SessionManager.decrypt_from_session(state, ciphertext, msg_data["header"]).decode()


# ── Flask маршруты ────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


# ── Socket.IO обработчики ─────────────────────────────────────────────────────

@socketio.on('connect')
def handle_connect():
    logger.info(f"Browser connected: {request.sid}")


@socketio.on('disconnect')
def handle_disconnect():
    for uname, sid in list(user_sids.items()):
        if sid == request.sid:
            del user_sids[uname]
            logger.info(f"User {uname} disconnected")
            break


@socketio.on('register')
def handle_register(data):
    username = (data.get('username') or '').strip()
    password = (data.get('password') or '').strip()
    if not username or not password:
        emit('register_response', {'error': 'Заполните все поля'})
        return

    # Генерируем ключи
    km = KeyManager()
    km.generate_identity_key()
    km.generate_spk()
    km.generate_opks(10)
    km.username = username

    sid = request.sid

    async def do_register():
        # Регистрируемся на MessageServer
        ws = await websockets.connect(MESSAGE_SERVER_URL)
        await ws.send(json.dumps({
            "type": "register",
            "username": username,
            "password": password,
            "bundle": km.export_bundle()
        }))
        resp = json.loads(await ws.recv())
        await ws.close()

        if resp.get("status") != "ok" and resp.get("message") != "User already exists":
            return False, resp.get("message", "Ошибка регистрации")

        # Логинимся
        ws2 = await websockets.connect(MESSAGE_SERVER_URL)
        await ws2.send(json.dumps({"type": "login", "username": username, "password": password}))
        resp2 = json.loads(await ws2.recv())
        if resp2.get("status") != "ok":
            await ws2.close()
            return False, "Ошибка входа после регистрации"

        user_ws[username] = ws2
        user_sids[username] = sid
        asyncio.ensure_future(_ws_listen(username, ws2, sid))
        return True, None

    try:
        user_keys[username] = km
        ok, err = _run_async(do_register())
        if ok:
            emit('register_response', {'status': 'ok', 'username': username})
            logger.info(f"Registered: {username}")
        else:
            del user_keys[username]
            emit('register_response', {'error': err or 'Ошибка регистрации'})
    except Exception as e:
        user_keys.pop(username, None)
        logger.error(f"Register error: {e}")
        emit('register_response', {'error': 'Сервер сообщений недоступен'})


@socketio.on('login')
def handle_login(data):
    username = (data.get('username') or '').strip()
    password = (data.get('password') or '').strip()
    if not username or not password:
        emit('login_response', {'error': 'Заполните все поля'})
        return

    # Создаём ключи если их нет (сессионные — для веб-демо)
    if username not in user_keys:
        km = KeyManager()
        km.generate_identity_key()
        km.generate_spk()
        km.generate_opks(10)
        km.username = username
        user_keys[username] = km

    sid = request.sid

    async def do_login():
        ws = await websockets.connect(MESSAGE_SERVER_URL)
        await ws.send(json.dumps({"type": "login", "username": username, "password": password}))
        resp = json.loads(await ws.recv())
        if resp.get("status") != "ok":
            await ws.close()
            return False
        user_ws[username] = ws
        user_sids[username] = sid
        asyncio.ensure_future(_ws_listen(username, ws, sid))
        return True

    try:
        ok = _run_async(do_login())
        if ok:
            join_room(sid)
            emit('login_response', {'status': 'ok', 'username': username})
            logger.info(f"Logged in: {username}")
        else:
            emit('login_response', {'error': 'Неверные учётные данные'})
    except Exception as e:
        logger.error(f"Login error: {e}")
        emit('login_response', {'error': 'Сервер сообщений недоступен'})


@socketio.on('send_message')
def handle_send_message(data):
    username  = data.get('username')
    recipient = data.get('recipient')
    text      = data.get('text')

    if not username or not recipient or not text:
        emit('error', {'message': 'Некорректные данные запроса'})
        return
    if username not in user_keys or username not in user_ws:
        emit('error', {'message': 'Сессия не установлена, войдите снова'})
        return

    km = user_keys[username]
    session_key = (username, recipient)

    async def do_send():
        ws = user_ws.get(username)
        if ws is None:
            return False

        if session_key not in user_sessions:
            # Запрашиваем ключевой бандл получателя
            await ws.send(json.dumps({"type": "get_bundle", "username": recipient}))
            raw = await asyncio.wait_for(ws.recv(), timeout=10)
            resp = json.loads(raw)
            if resp.get("type") != "bundle":
                return False

            state, ek_pub, _ = SessionManager.initiate_session(
                km.ik_x25519_priv, km.ik_x25519_pub, resp["bundle"], None
            )
            user_sessions[session_key] = state

            ciphertext, header = SessionManager.encrypt_for_session(state, text.encode())
            message_data = {
                "type":      "prekey",
                "ik_a_pub":  base64.b64encode(km.ik_x25519_pub).decode(),
                "ek_a_pub":  base64.b64encode(ek_pub).decode(),
                "opk_id":    None,
                "ciphertext": base64.b64encode(ciphertext).decode(),
                "header":    header
            }
        else:
            state = user_sessions[session_key]
            ciphertext, header = SessionManager.encrypt_for_session(state, text.encode())
            message_data = {
                "type":      "message",
                "ciphertext": base64.b64encode(ciphertext).decode(),
                "header":    header
            }

        await ws.send(json.dumps({"type": "send", "recipient": recipient, "message": message_data}))
        raw = await asyncio.wait_for(ws.recv(), timeout=10)
        resp = json.loads(raw)
        return resp.get("status") == "sent"

    try:
        ok = _run_async(do_send())
        if ok:
            emit('message_sent', {'recipient': recipient, 'text': text})
        else:
            emit('error', {'message': 'Не удалось отправить сообщение'})
    except Exception as e:
        logger.error(f"Send error ({username} → {recipient}): {e}")
        emit('error', {'message': f'Ошибка отправки: {e}'})


@socketio.on('logout')
def handle_logout(data):
    username = data.get('username')
    if username:
        ws = user_ws.pop(username, None)
        if ws:
            async def close_ws():
                await ws.close()
            _run_async(close_ws(), timeout=5)
        user_sids.pop(username, None)
        logger.info(f"Logged out: {username}")


# ── Точка входа ───────────────────────────────────────────────────────────────

if __name__ == '__main__':
    _ensure_bg_loop()
    logger.info("=" * 55)
    logger.info("  SecureChat веб-сервер: http://localhost:5000")
    logger.info("  Протокол: X3DH + Double Ratchet + AES-256-GCM")
    logger.info("=" * 55)
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)
