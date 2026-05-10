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
from log_utils import get_file_logger, h, b64s, SEP, SEP2
from flowchart_api import get_step_logs

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)
_flog = get_file_logger("webapp", "webapp.log")


class _MemHandler(logging.Handler):
    """Хранит последние N лог-записей в памяти для страницы /logs."""
    def __init__(self, maxlen: int = 600):
        super().__init__()
        self._buf: collections.deque = collections.deque(maxlen=maxlen)

    def emit(self, record: logging.LogRecord):
        from datetime import datetime
        self._buf.append({
            "time":  datetime.fromtimestamp(record.created).strftime("%H:%M:%S"),
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
    _flog.info(SEP)
    _flog.info(f"[WEBAPP/RECV] ▶ СТАРТ  Получение и расшифровка: {sender} → {username}")
    _flog.info(f"[WEBAPP/RECV]   Тип сообщения: {msg_data.get('type')}")

    if username not in _users:
        raise ValueError("Ключи не найдены")
    km = _users[username].km
    key = (username, sender)

    if key not in _sessions:
        if msg_data.get("type") != "prekey":
            _flog.error(f"[WEBAPP/RECV] ✗ Ожидался prekey, получен: {msg_data.get('type')}")
            raise ValueError("Ожидается prekey-сообщение")

        ik_a_pub = base64.b64decode(msg_data["ik_a_pub"])
        ek_a_pub = base64.b64decode(msg_data["ek_a_pub"])
        opk_id   = msg_data.get("opk_id")
        _flog.info(f"[WEBAPP/RECV]   X3DH receive_session — новая сессия с '{sender}'")
        _flog.info(f"[WEBAPP/RECV]     IK_A_pub = {h(ik_a_pub)}")
        _flog.info(f"[WEBAPP/RECV]     EK_A_pub = {h(ek_a_pub)}")
        _flog.info(f"[WEBAPP/RECV]     OPK_id   = {opk_id}")
        _flog.info(f"[WEBAPP/RECV]     IK_B_pub = {h(km.ik_x25519_pub)}")
        _flog.info(f"[WEBAPP/RECV]     SPK_B    = {h(km.spk_pub)}")
        _flog.info(f"[WEBAPP/RECV]     OPK пул  = {len(km.opks)} ключей")

        # Build OPK priv dict: base64(pub) → priv, so receive_session can compute dh4
        opk_priv_dict = {base64.b64encode(pub).decode(): priv for priv, pub in km.opks}
        state = SessionManager.receive_session(
            km.ik_x25519_priv, km.ik_x25519_pub,
            km.spk_priv, km.spk_pub,
            opk_priv_dict,
            ik_a_pub,
            ek_a_pub,
            opk_id
        )
        _sessions[key] = state
        _flog.info(f"[WEBAPP/RECV]   X3DH завершён — сессия создана")
    else:
        _flog.info(f"[WEBAPP/RECV]   Существующая сессия — Double Ratchet decrypt")

    ct = base64.b64decode(msg_data["ciphertext"])
    _flog.info(f"[WEBAPP/RECV]   Расшифровка: ct={len(ct)} байт, hdr={msg_data.get('header')}")
    plaintext = SessionManager.decrypt_from_session(_sessions[key], ct, msg_data["header"])
    _flog.info(f"[WEBAPP/RECV] ✓ ГОТОВО  Расшифровано: «{plaintext[:60].decode(errors='replace')}»")
    return plaintext.decode()


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


@app.route('/flowchart')
def flowchart_page():
    return render_template('flowchart.html')


@app.route('/api/flowchart/step/<step_id>')
def api_flowchart_step(step_id):
    data = get_step_logs(step_id)
    return jsonify(data)


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


def _key_path(username: str) -> str:
    key_dir = os.getenv("KEY_DIR", "/app/keys")
    return os.path.join(key_dir, f"{username}.json")


def _load_or_create_km(username: str) -> tuple:
    """Returns (km, loaded_from_disk: bool)."""
    path = _key_path(username)
    _flog.info(SEP)
    _flog.info(f"[WEBAPP/KEYS] ▶ Загрузка/генерация ключей для '{username}'")
    _flog.info(f"[WEBAPP/KEYS]   Путь к файлу: {path}")
    if os.path.exists(path):
        try:
            km = KeyManager.load_keys(path)
            _flog.info(f"[WEBAPP/KEYS] ✓ Ключи загружены с диска — IK={h(km.ik_x25519_pub)}, OPK={len(km.opks)}")
            logger.info(f"Loaded existing keys for {username}")
            return km, True
        except Exception as e:
            _flog.warning(f"[WEBAPP/KEYS] ✗ Ошибка загрузки: {e} — генерируем новые")
            logger.warning(f"Failed to load keys for {username}: {e}, generating new ones")
    km = KeyManager(storage_path=path)
    km.generate_identity_key()
    km.generate_spk()
    km.generate_opks(10)
    km.username = username
    _flog.info(f"[WEBAPP/KEYS] ✓ Новые ключи сгенерированы — IK={h(km.ik_x25519_pub)}, OPK={len(km.opks)}")
    return km, False


@socketio.on('register')
def handle_register(data):
    username = (data.get('username') or '').strip()
    password = (data.get('password') or '').strip()
    _flog.info(SEP2)
    _flog.info(f"[WEBAPP/REGISTER] ▶ СТАРТ  Регистрация пользователя '{username}'")
    if not username or not password:
        _flog.warning("[WEBAPP/REGISTER] ✗ Пустые поля username/password")
        emit('register_response', {'error': 'Заполните все поля'})
        return

    km, keys_from_disk = _load_or_create_km(username)

    sid = request.sid

    async def do_register():
        _flog.info(f"[WEBAPP/REGISTER]   Подключение к MessageServer: {MESSAGE_SERVER_URL}")
        ws_reg = await websockets.connect(MESSAGE_SERVER_URL)
        bundle = km.export_bundle()
        _flog.info(f"[WEBAPP/REGISTER]   Отправка bundle:")
        _flog.info(f"[WEBAPP/REGISTER]     IK_x25519 = {b64s(base64.b64decode(bundle['ik_x25519']))}")
        _flog.info(f"[WEBAPP/REGISTER]     SPK       = {b64s(base64.b64decode(bundle['spk']))}")
        _flog.info(f"[WEBAPP/REGISTER]     OPK count = {len(bundle['opks'])}")
        await ws_reg.send(json.dumps({
            "type": "register",
            "username": username,
            "password": password,
            "bundle": bundle
        }))
        resp = json.loads(await ws_reg.recv())
        await ws_reg.close()
        _flog.info(f"[WEBAPP/REGISTER]   Ответ сервера: {resp}")

        if resp.get("status") != "ok":
            if resp.get("message") == "User already exists":
                if not keys_from_disk:
                    # Fresh keys but user already in KDS — keys won't match, refuse
                    _flog.error("[WEBAPP/REGISTER] ✗ Пользователь существует в KDS, но локальных ключей нет — несоответствие!")
                    raise ValueError(
                        "Пользователь уже зарегистрирован, но локальные ключи отсутствуют. "
                        "Сбросьте данные сервера и зарегистрируйтесь заново."
                    )
                _flog.info("[WEBAPP/REGISTER]   Пользователь существует, ключи на диске совпадают — входим")
            else:
                raise ValueError(resp.get("message", "Ошибка регистрации"))
        else:
            # Fresh registration success — persist keys now
            _flog.info("[WEBAPP/REGISTER]   Регистрация успешна — сохраняем ключи на диск")
            km.save_keys(username)

        _flog.info(f"[WEBAPP/REGISTER]   Выполняем login после регистрации...")
        st = await _connect_and_login(username, password, sid)
        st.km = km
        _users[username] = st
        _flog.info(f"[WEBAPP/REGISTER] ✓ ГОТОВО  Пользователь '{username}' зарегистрирован и вошёл")

    try:
        if username not in _users:
            _users[username] = UserState(km=km, ws=None, sid=sid)
        else:
            _users[username].km = km

        _run_async(do_register())
        emit('register_response', {'status': 'ok', 'username': username})
        logger.info(f"Registered: {username}")
    except Exception as e:
        _users.pop(username, None)
        _flog.error(f"[WEBAPP/REGISTER] ✗ Ошибка регистрации: {e}")
        logger.error(f"Register error: {e}")
        emit('register_response', {'error': str(e)})


@socketio.on('login')
def handle_login(data):
    username = (data.get('username') or '').strip()
    password = (data.get('password') or '').strip()
    _flog.info(SEP2)
    _flog.info(f"[WEBAPP/LOGIN] ▶ СТАРТ  Вход пользователя '{username}'")
    if not username or not password:
        _flog.warning("[WEBAPP/LOGIN] ✗ Пустые поля username/password")
        emit('login_response', {'error': 'Заполните все поля'})
        return

    sid = request.sid

    async def do_login():
        # Always evaluate key state inside the coroutine — avoids stale outer-scope
        # flags from earlier failed or ghost login attempts.
        km, keys_from_disk = _load_or_create_km(username)
        _flog.info(f"[WEBAPP/LOGIN]   Ключи {'загружены с диска' if keys_from_disk else 'сгенерированы новые'}")
        _flog.info(f"[WEBAPP/LOGIN]   IK_x25519_pub = {h(km.ik_x25519_pub)}")
        _flog.info(f"[WEBAPP/LOGIN]   SPK_pub       = {h(km.spk_pub)}")
        _flog.info(f"[WEBAPP/LOGIN]   OPK count     = {len(km.opks)}")

        if username not in _users or _users[username].ws is None:
            _users[username] = UserState(km=km, ws=None, sid=sid)
        else:
            _users[username].km = km

        _flog.info(f"[WEBAPP/LOGIN]   Подключение к MessageServer и аутентификация...")
        st = await _connect_and_login(username, password, sid)
        _flog.info(f"[WEBAPP/LOGIN]   Аутентификация успешна, WebSocket установлен")

        if not keys_from_disk:
            _flog.info(f"[WEBAPP/LOGIN]   Нет файла ключей — отправляем новый bundle в KDS")
            bundle = st.km.export_bundle()
            _flog.info(f"[WEBAPP/LOGIN]     bundle.IK   = {b64s(base64.b64decode(bundle['ik_x25519']))}")
            _flog.info(f"[WEBAPP/LOGIN]     bundle.SPK  = {b64s(base64.b64decode(bundle['spk']))}")
            _flog.info(f"[WEBAPP/LOGIN]     bundle.OPKs = {len(bundle['opks'])} шт.")
            logger.info(f"No key file for {username} — pushing fresh bundle to KDS")
            await st.ws.send(json.dumps({
                "type": "update_bundle",
                "bundle": bundle,
            }))
            resp = await _ws_recv(st, timeout=10)
            _flog.info(f"[WEBAPP/LOGIN]   Ответ KDS update_bundle: {resp}")
            if resp.get("status") == "ok":
                st.km.save_keys(username)
                cleared = [k for k in _sessions if username in k]
                for k in cleared:
                    del _sessions[k]
                _flog.info(f"[WEBAPP/LOGIN]   Bundle обновлён в KDS, ключи сохранены, сессий очищено: {len(cleared)}")
                logger.info(f"Updated KDS bundle and saved new keys for {username}")
            else:
                _flog.warning(f"[WEBAPP/LOGIN]   Bundle update не удался: {resp}")
                logger.warning(f"Bundle update failed for {username}: {resp}")
        else:
            _flog.info(f"[WEBAPP/LOGIN]   Ключи с диска совпадают с KDS — bundle не обновляем")

        _flog.info(f"[WEBAPP/LOGIN] ✓ ГОТОВО  Пользователь '{username}' вошёл в систему")

    try:
        _run_async(do_login())
        join_room(sid)
        emit('login_response', {'status': 'ok', 'username': username})
        logger.info(f"Logged in: {username}")
    except Exception as e:
        _flog.error(f"[WEBAPP/LOGIN] ✗ Ошибка входа: {e}")
        logger.error(f"Login error: {e}")
        emit('login_response', {'error': 'Неверные учётные данные или сервер недоступен'})


@socketio.on('send_message')
def handle_send_message(data):
    username  = data.get('username')
    recipient = data.get('recipient')
    text      = data.get('text')

    _flog.info(SEP2)
    _flog.info(f"[WEBAPP/SEND] ▶ СТАРТ  Отправка сообщения: {username} → {recipient}")
    _flog.info(f"[WEBAPP/SEND]   Текст: «{text[:50]}{'...' if len(text or '') > 50 else ''}»")

    if not username or not recipient or not text:
        _flog.warning("[WEBAPP/SEND] ✗ Некорректные данные")
        emit('error', {'message': 'Некорректные данные'})
        return
    if username not in _users or _users[username].ws is None:
        _flog.warning(f"[WEBAPP/SEND] ✗ Сессия не установлена для '{username}'")
        emit('error', {'message': 'Сессия не установлена'})
        return

    st = _users[username]
    km = st.km
    key = (username, recipient)

    async def do_send():
        if key not in _sessions:
            _flog.info(f"[WEBAPP/SEND]   Новая сессия — запрашиваем bundle у KDS для '{recipient}'")
            await st.ws.send(json.dumps({"type": "get_bundle", "username": recipient}))
            resp = await _ws_recv(st, timeout=10)
            if resp.get("type") != "bundle":
                _flog.error(f"[WEBAPP/SEND] ✗ Не получен bundle: {resp}")
                raise ValueError("Не удалось получить ключи получателя")

            bundle = resp["bundle"]
            _flog.info(f"[WEBAPP/SEND]   Bundle получен:")
            _flog.info(f"[WEBAPP/SEND]     IK_B      = {b64s(base64.b64decode(bundle['ik_x25519']))}")
            _flog.info(f"[WEBAPP/SEND]     SPK_B     = {b64s(base64.b64decode(bundle['spk']))}")
            opk_entry = bundle.get("opk") or {}
            opk_pub_b64 = opk_entry.get("public")
            _flog.info(f"[WEBAPP/SEND]     OPK_B     = {b64s(base64.b64decode(opk_pub_b64)) if opk_pub_b64 else 'нет'}")

            # Извлекаем OPK id ДО initiate_session, чтобы передать получателю
            opk_id = opk_pub_b64

            _flog.info(f"[WEBAPP/SEND]   Инициация X3DH сессии (initiate_session)...")
            rstate, ek_pub, _ = SessionManager.initiate_session(
                km.ik_x25519_priv, km.ik_x25519_pub, bundle, None
            )
            _sessions[key] = rstate
            _flog.info(f"[WEBAPP/SEND]   X3DH завершён — EK_A_pub = {h(ek_pub)}")

            ct, hdr = SessionManager.encrypt_for_session(rstate, text.encode())
            _flog.info(f"[WEBAPP/SEND]   Шифрование (prekey): ct={len(ct)} байт, hdr={hdr}")
            msg_data = {
                "type":       "prekey",
                "ik_a_pub":   base64.b64encode(km.ik_x25519_pub).decode(),
                "ek_a_pub":   base64.b64encode(ek_pub).decode(),
                "opk_id":     opk_id,
                "ciphertext": base64.b64encode(ct).decode(),
                "header":     hdr,
            }
        else:
            rstate = _sessions[key]
            _flog.info(f"[WEBAPP/SEND]   Существующая сессия — Double Ratchet encrypt")
            ct, hdr = SessionManager.encrypt_for_session(rstate, text.encode())
            _flog.info(f"[WEBAPP/SEND]   Шифрование (ratchet): ct={len(ct)} байт, hdr={hdr}")
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
        _flog.info(f"[WEBAPP/SEND]   Ответ сервера: {resp}")
        return resp.get("status") == "sent"

    try:
        ok = _run_async(do_send())
        if ok:
            _flog.info(f"[WEBAPP/SEND] ✓ ГОТОВО  Сообщение доставлено: {username} → {recipient}")
            emit('message_sent', {'recipient': recipient, 'text': text})
        else:
            _flog.warning(f"[WEBAPP/SEND] ✗ Сервер не подтвердил доставку")
            emit('error', {'message': 'Не удалось отправить'})
    except Exception as e:
        _flog.error(f"[WEBAPP/SEND] ✗ Ошибка: {e}")
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
    _flog.info(SEP2)
    _flog.info("[WEBAPP/INIT] SecureChat веб-сервер запущен: http://localhost:5000")
    _flog.info("[WEBAPP/INIT] Протокол: X3DH + Double Ratchet + AES-256-GCM")
    _flog.info(SEP2)
    logger.info("=" * 55)
    logger.info("  SecureChat веб-сервер: http://localhost:5000")
    logger.info("  Протокол: X3DH + Double Ratchet + AES-256-GCM")
    logger.info("=" * 55)
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)
