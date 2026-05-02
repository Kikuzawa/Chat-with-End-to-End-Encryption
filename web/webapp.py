"""
Веб-сервер E2EE чата (Flask + Socket.IO).

Архитектура WebSocket-диспетчера:
  Один фоновый loop читает ВСЕ сообщения от MessageServer и маршрутизирует:
    • type == "message"           → socketio.emit (входящее сообщение)
    • type in {bundle, ack, error, ...} → response_queue (ответ на запрос)

  Это устраняет ошибку "cannot call recv while another coroutine is already
  waiting" — ws.recv() вызывается строго в одном месте (_ws_dispatcher).
"""
import sys
import os
import json
import asyncio
import threading
import logging
import base64
import collections
from dataclasses import dataclass, field

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, render_template, request, jsonify
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


class _MemHandler(logging.Handler):
    """Хранит последние N лог-записей в памяти для страницы /logs."""
    def __init__(self, maxlen: int = 600):
        super().__init__()
        self._buf: collections.deque = collections.deque(maxlen=maxlen)

    def emit(self, record: logging.LogRecord):
        self._buf.append({
            "time":  self.formatTime(record, "%H:%M:%S"),
            "level": record.levelname,
            "name":  record.name,
            "msg":   record.getMessage(),
        })

    def records(self):
        return list(self._buf)


_mem_handler = _MemHandler()
_mem_handler.setLevel(logging.DEBUG)
logging.getLogger().addHandler(_mem_handler)

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

MESSAGE_SERVER_URL = os.getenv("SERVER_URL", "ws://localhost:8000/ws")

# ── Фоновый asyncio event loop ────────────────────────────────────────────────
_bg_loop: asyncio.AbstractEventLoop = None


def _ensure_bg_loop():
    global _bg_loop
    if _bg_loop is not None and _bg_loop.is_running():
        return
    _bg_loop = asyncio.new_event_loop()
    t = threading.Thread(target=_bg_loop.run_forever, daemon=True, name="ws-loop")
    t.start()


def _run_async(coro, timeout: float = 20.0):
    _ensure_bg_loop()
    return asyncio.run_coroutine_threadsafe(coro, _bg_loop).result(timeout=timeout)


# ── Состояние пользователя ────────────────────────────────────────────────────
@dataclass
class UserState:
    km: KeyManager
    ws: object                               # websockets connection
    sid: str                                 # socket.io session id
    response_queue: asyncio.Queue = field(default_factory=asyncio.Queue)
    listener_task: object = None             # asyncio.Task


# username → UserState
_users: dict[str, UserState] = {}
# (username, recipient) → RatchetState
_sessions: dict[tuple, object] = {}


# ── WebSocket диспетчер ───────────────────────────────────────────────────────

async def _ws_dispatcher(username: str, state: UserState):
    """
    Читает ВСЕ сообщения от MessageServer в одном месте.
    Входящие чат-сообщения → socketio.emit.
    Ответы на запросы (bundle, ack, error, login, register) → response_queue.
    """
    try:
        async for raw in state.ws:
            try:
                data = json.loads(raw)
            except Exception:
                continue

            msg_type = data.get("type")

            if msg_type == "message":
                sender = data.get("sender", "")
                msg_data = data.get("data", {})
                try:
                    text = _decrypt_incoming(username, sender, msg_data)
                    socketio.emit('message', {'sender': sender, 'text': text}, room=state.sid)
                except Exception as e:
                    logger.error(f"Decrypt error ({username} ← {sender}): {e}")
                    socketio.emit('message',
                                  {'sender': sender, 'text': '[Ошибка расшифровки]', 'error': True},
                                  room=state.sid)
            else:
                # Ответ на запрос — кладём в очередь
                await state.response_queue.put(data)

    except Exception as e:
        logger.info(f"Dispatcher ended for {username}: {e}")


async def _ws_recv(state: UserState, timeout: float = 10.0) -> dict:
    """Получает следующий ответ из очереди (не из ws.recv напрямую!)."""
    return await asyncio.wait_for(state.response_queue.get(), timeout=timeout)


# ── Криптография ──────────────────────────────────────────────────────────────

def _decrypt_incoming(username: str, sender: str, msg_data: dict) -> str:
    if username not in _users:
        raise ValueError("Ключи не найдены")
    km = _users[username].km
    key = (username, sender)

    if key not in _sessions:
        if msg_data.get("type") != "prekey":
            raise ValueError("Ожидается prekey-сообщение")
        # Build OPK priv dict: base64(pub) → priv, so receive_session can compute dh4
        opk_priv_dict = {base64.b64encode(pub).decode(): priv for priv, pub in km.opks}
        state = SessionManager.receive_session(
            km.ik_x25519_priv, km.ik_x25519_pub,
            km.spk_priv, km.spk_pub,
            opk_priv_dict,
            base64.b64decode(msg_data["ik_a_pub"]),
            base64.b64decode(msg_data["ek_a_pub"]),
            msg_data.get("opk_id")
        )
        _sessions[key] = state

    ct = base64.b64decode(msg_data["ciphertext"])
    return SessionManager.decrypt_from_session(_sessions[key], ct, msg_data["header"]).decode()


# ── Подключение к MessageServer ───────────────────────────────────────────────

async def _connect_and_login(username: str, password: str, sid: str) -> UserState:
    """Открывает WS, логинится, запускает диспетчер. Возвращает UserState."""
    ws = await websockets.connect(MESSAGE_SERVER_URL)
    km = _users[username].km if username in _users else None

    st = UserState(km=km, ws=ws, sid=sid,
                   response_queue=asyncio.Queue())
    if username in _users:
        st.km = _users[username].km
    _users[username] = st

    await ws.send(json.dumps({"type": "login", "username": username, "password": password}))

    # Запускаем диспетчер ДО первого recv, чтобы не пропустить сообщения
    st.listener_task = asyncio.ensure_future(_ws_dispatcher(username, st))

    resp = await _ws_recv(st, timeout=10)
    if resp.get("status") != "ok":
        st.listener_task.cancel()
        await ws.close()
        raise ValueError(resp.get("message", "Ошибка входа"))

    return st


# ── Flask маршруты ────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/logs')
def logs_page():
    return render_template('logs.html')


@app.route('/api/logs')
def api_logs():
    since = request.args.get('since', 0, type=int)
    all_records = _mem_handler.records()
    return jsonify({
        "logs":  all_records[since:],
        "total": len(all_records),
    })


# ── Socket.IO обработчики ─────────────────────────────────────────────────────

@socketio.on('connect')
def handle_connect():
    logger.info(f"Browser connected: {request.sid}")


@socketio.on('disconnect')
def handle_disconnect():
    for uname, st in list(_users.items()):
        if st.sid == request.sid:
            logger.info(f"Browser disconnected: {uname}")
            async def _cleanup(s=st):
                if s.listener_task:
                    s.listener_task.cancel()
                if s.ws:
                    try:
                        await s.ws.close()
                    except Exception:
                        pass
            try:
                _run_async(_cleanup(), timeout=3)
            except Exception:
                pass
            # km сохраняем — он нужен при повторном входе (ключи совпадут с KDS)
            st.ws = None
            st.listener_task = None
            break


@socketio.on('register')
def handle_register(data):
    username = (data.get('username') or '').strip()
    password = (data.get('password') or '').strip()
    if not username or not password:
        emit('register_response', {'error': 'Заполните все поля'})
        return

    km = KeyManager()
    km.generate_identity_key()
    km.generate_spk()
    km.generate_opks(10)
    km.username = username

    sid = request.sid

    async def do_register():
        # Регистрация
        ws_reg = await websockets.connect(MESSAGE_SERVER_URL)
        await ws_reg.send(json.dumps({
            "type": "register",
            "username": username,
            "password": password,
            "bundle": km.export_bundle()
        }))
        resp = json.loads(await ws_reg.recv())
        await ws_reg.close()
        if resp.get("status") != "ok" and resp.get("message") != "User already exists":
            raise ValueError(resp.get("message", "Ошибка регистрации"))

        # Логин
        st = await _connect_and_login(username, password, sid)
        st.km = km
        _users[username] = st

    try:
        # Временно ставим km, чтобы _connect_and_login мог его найти
        if username not in _users:
            _users[username] = UserState(km=km, ws=None, sid=sid)
        else:
            _users[username].km = km

        _run_async(do_register())
        emit('register_response', {'status': 'ok', 'username': username})
        logger.info(f"Registered: {username}")
    except Exception as e:
        _users.pop(username, None)
        logger.error(f"Register error: {e}")
        emit('register_response', {'error': str(e)})


@socketio.on('login')
def handle_login(data):
    username = (data.get('username') or '').strip()
    password = (data.get('password') or '').strip()
    if not username or not password:
        emit('login_response', {'error': 'Заполните все поля'})
        return

    if username not in _users:
        km = KeyManager()
        km.generate_identity_key()
        km.generate_spk()
        km.generate_opks(10)
        km.username = username
        _users[username] = UserState(km=km, ws=None, sid=request.sid)

    sid = request.sid

    try:
        st = _run_async(_connect_and_login(username, password, sid))
        join_room(sid)
        emit('login_response', {'status': 'ok', 'username': username})
        logger.info(f"Logged in: {username}")
    except Exception as e:
        logger.error(f"Login error: {e}")
        emit('login_response', {'error': 'Неверные учётные данные или сервер недоступен'})


@socketio.on('send_message')
def handle_send_message(data):
    username  = data.get('username')
    recipient = data.get('recipient')
    text      = data.get('text')

    if not username or not recipient or not text:
        emit('error', {'message': 'Некорректные данные'})
        return
    if username not in _users or _users[username].ws is None:
        emit('error', {'message': 'Сессия не установлена'})
        return

    st = _users[username]
    km = st.km
    key = (username, recipient)

    async def do_send():
        if key not in _sessions:
            # Запрашиваем бандл получателя
            await st.ws.send(json.dumps({"type": "get_bundle", "username": recipient}))
            resp = await _ws_recv(st, timeout=10)
            if resp.get("type") != "bundle":
                raise ValueError("Не удалось получить ключи получателя")

            bundle = resp["bundle"]
            # Извлекаем OPK id ДО initiate_session, чтобы передать получателю
            opk_id = (bundle.get("opk") or {}).get("public")

            rstate, ek_pub, _ = SessionManager.initiate_session(
                km.ik_x25519_priv, km.ik_x25519_pub, bundle, None
            )
            _sessions[key] = rstate

            ct, hdr = SessionManager.encrypt_for_session(rstate, text.encode())
            msg_data = {
                "type":       "prekey",
                "ik_a_pub":   base64.b64encode(km.ik_x25519_pub).decode(),
                "ek_a_pub":   base64.b64encode(ek_pub).decode(),
                "opk_id":     opk_id,   # теперь передаём реальный OPK pub
                "ciphertext": base64.b64encode(ct).decode(),
                "header":     hdr,
            }
        else:
            rstate = _sessions[key]
            ct, hdr = SessionManager.encrypt_for_session(rstate, text.encode())
            msg_data = {
                "type":       "message",
                "ciphertext": base64.b64encode(ct).decode(),
                "header":     hdr,
            }

        await st.ws.send(json.dumps({
            "type":      "send",
            "recipient": recipient,
            "message":   msg_data,
        }))
        resp = await _ws_recv(st, timeout=10)
        return resp.get("status") == "sent"

    try:
        ok = _run_async(do_send())
        if ok:
            emit('message_sent', {'recipient': recipient, 'text': text})
        else:
            emit('error', {'message': 'Не удалось отправить'})
    except Exception as e:
        logger.error(f"Send error ({username} → {recipient}): {e}")
        emit('error', {'message': f'Ошибка отправки: {e}'})


@socketio.on('logout')
def handle_logout(data):
    username = data.get('username')
    st = _users.pop(username, None)
    if st and st.ws:
        async def _close():
            if st.listener_task:
                st.listener_task.cancel()
            await st.ws.close()
        _run_async(_close(), timeout=5)
    logger.info(f"Logged out: {username}")


# ── Точка входа ───────────────────────────────────────────────────────────────

if __name__ == '__main__':
    _ensure_bg_loop()
    logger.info("=" * 55)
    logger.info("  SecureChat веб-сервер: http://localhost:5000")
    logger.info("  Протокол: X3DH + Double Ratchet + AES-256-GCM")
    logger.info("=" * 55)
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)
