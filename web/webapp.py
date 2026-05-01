"""
Веб-интерфейс с криптографией через Python-клиент
"""
import sys
import os
import json
import asyncio
import threading
import logging
import base64

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, render_template, request, jsonify, session
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room, leave_room
import secrets
from datetime import datetime
import websockets

# Добавляем криптографию
from crypto.keymanager import KeyManager
from crypto.sessionmanager import SessionManager

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S')
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Хранилище
users = {}
user_keys = {}  # username -> KeyManager
user_sessions = {}  # (username, recipient) -> RatchetState
ws_connections = {}  # username -> WebSocket

# Подключение к MessageServer
MESSAGE_SERVER_URL = "ws://localhost:8000/ws"

async def connect_to_message_server(username, password):
    """Подключается к MessageServer и логинится"""
    try:
        ws = await websockets.connect(MESSAGE_SERVER_URL)
        ws_connections[username] = ws
        
        # Логинимся
        await ws.send(json.dumps({
            "type": "login",
            "username": username,
            "password": password
        }))
        
        response = await ws.recv()
        data = json.loads(response)
        
        if data.get("status") == "ok":
            logger.info(f"Подключен к MessageServer как {username}")
            return ws
        else:
            logger.error(f"Ошибка логина на MessageServer: {data}")
            return None
    except Exception as e:
        logger.error(f"Ошибка подключения к MessageServer: {e}")
        return None

async def listen_for_messages(username, ws, sid):
    """Слушает входящие сообщения от MessageServer"""
    try:
        while True:
            message = await ws.recv()
            data = json.loads(message)
            
            if data.get("type") == "message":
                sender = data["sender"]
                msg_data = data["data"]
                
                # Расшифровываем сообщение
                try:
                    decrypted = decrypt_message(username, sender, msg_data)
                    # Отправляем в браузер
                    socketio.emit('message', {
                        'sender': sender,
                        'text': decrypted,
                        'type': 'message'
                    }, room=sid)
                    logger.info(f"Сообщение от {sender} для {username}: {decrypted}")
                except Exception as e:
                    logger.error(f"Ошибка расшифровки: {e}")
                    socketio.emit('message', {
                        'sender': sender,
                        'text': '[Ошибка расшифровки]',
                        'type': 'error'
                    }, room=sid)
            
            elif data.get("type") == "bundle":
                logger.info(f"Получен бандл для {username}")
                socketio.emit('bundle_received', {
                    'username': data.get('username')
                }, room=sid)
                
    except Exception as e:
        logger.error(f"Ошибка в listen_for_messages: {e}")

def decrypt_message(username, sender, msg_data):
    """Расшифровывает входящее сообщение"""
    session_key = (username, sender)
    
    if session_key not in user_sessions:
        # Создаем новую сессию из prekey сообщения
        if msg_data.get("type") == "prekey":
            km = user_keys[username]
            
            init_ik_pub = base64.b64decode(msg_data["ik_a_pub"])
            init_ek_pub = base64.b64decode(msg_data["ek_a_pub"])
            
            state = SessionManager.receive_session(
                km.ik_x25519_priv, km.ik_x25519_pub,
                km.spk_priv, km.spk_pub,
                {}, init_ik_pub, init_ek_pub, None
            )
            user_sessions[session_key] = state
            
            ciphertext = base64.b64decode(msg_data["ciphertext"])
            header = msg_data["header"]
            return SessionManager.decrypt_from_session(state, ciphertext, header).decode()
    
    if session_key in user_sessions:
        state = user_sessions[session_key]
        ciphertext = base64.b64decode(msg_data["ciphertext"])
        header = msg_data["header"]
        return SessionManager.decrypt_from_session(state, ciphertext, header).decode()
    
    return "[Невозможно расшифровать]"

@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('connect')
def handle_connect():
    logger.info(f"Браузер подключен: {request.sid}")

@socketio.on('register')
def handle_register(data):
    username = data.get('username')
    password = data.get('password')
    
    if username in users:
        emit('register_response', {'error': 'Пользователь уже существует'})
        return
    
    # Создаем ключи
    km = KeyManager()
    km.generate_identity_key()
    km.generate_spk()
    km.generate_opks(10)
    km.username = username
    
    users[username] = {'password': password}
    user_keys[username] = km
    
    # Подключаемся к MessageServer и регистрируем там
    async def register_on_server():
        ws = await connect_to_message_server(username, password)
        if ws:
            # Отправляем бандл
            bundle = km.export_bundle()
            await ws.send(json.dumps({
                "type": "register",
                "username": username,
                "password": password,
                "bundle": bundle
            }))
            response = await ws.recv()
            logger.info(f"Регистрация на MessageServer: {response}")
            
            # Переподключаемся с логином
            await ws.close()
            ws = await connect_to_message_server(username, password)
            
            # Начинаем слушать сообщения
            asyncio.create_task(listen_for_messages(username, ws, request.sid))
    
    asyncio.run(register_on_server())
    
    emit('register_response', {'status': 'ok', 'username': username})
    logger.info(f"Пользователь {username} зарегистрирован")

@socketio.on('login')
def handle_login(data):
    username = data.get('username')
    password = data.get('password')
    
    if username not in users or users[username]['password'] != password:
        emit('login_response', {'error': 'Неверные учетные данные'})
        return
    
    join_room(request.sid)
    
    async def login_to_server():
        ws = await connect_to_message_server(username, password)
        if ws:
            asyncio.create_task(listen_for_messages(username, ws, request.sid))
    
    asyncio.run(login_to_server())
    
    emit('login_response', {'status': 'ok', 'username': username})
    logger.info(f"Пользователь {username} вошел")

@socketio.on('send_message')
def handle_send_message(data):
    username = data.get('username')
    recipient = data.get('recipient')
    text = data.get('text')
    
    if username not in user_keys:
        emit('error', {'message': 'Ключи не найдены'})
        return
    
    async def send_encrypted():
        ws = ws_connections.get(username)
        if not ws:
            emit('error', {'message': 'Нет подключения к серверу'})
            return
        
        km = user_keys[username]
        session_key = (username, recipient)
        
        if session_key not in user_sessions:
            # Запрашиваем бандл
            await ws.send(json.dumps({
                "type": "get_bundle",
                "username": recipient
            }))
            response = await ws.recv()
            bundle_data = json.loads(response)
            
            if bundle_data.get("type") != "bundle":
                emit('error', {'message': 'Не удалось получить ключи пользователя'})
                return
            
            bundle = bundle_data["bundle"]
            
            # Создаем сессию
            state, ek_pub, _ = SessionManager.initiate_session(
                km.ik_x25519_priv, km.ik_x25519_pub, bundle, None
            )
            user_sessions[session_key] = state
            
            ciphertext, header = SessionManager.encrypt_for_session(state, text.encode())
            message_data = {
                "type": "prekey",
                "ik_a_pub": base64.b64encode(km.ik_x25519_pub).decode(),
                "ek_a_pub": base64.b64encode(ek_pub).decode(),
                "opk_id": None,
                "ciphertext": base64.b64encode(ciphertext).decode(),
                "header": header
            }
        else:
            state = user_sessions[session_key]
            ciphertext, header = SessionManager.encrypt_for_session(state, text.encode())
            message_data = {
                "type": "message",
                "ciphertext": base64.b64encode(ciphertext).decode(),
                "header": header
            }
        
        # Отправляем
        await ws.send(json.dumps({
            "type": "send",
            "recipient": recipient,
            "message": message_data
        }))
        
        emit('message_sent', {'recipient': recipient, 'text': text})
        logger.info(f"Сообщение от {username} для {recipient}: {text}")
    
    asyncio.run(send_encrypted())

if __name__ == '__main__':
    logger.info("=" * 50)
    logger.info("Веб-сервер с криптографией: http://localhost:5000")
    logger.info("=" * 50)
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)