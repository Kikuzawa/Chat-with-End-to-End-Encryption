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

redis_pool = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global redis_pool
    try:
        redis_pool = await aioredis.from_url(REDIS_URL, decode_responses=True)
        await redis_pool.ping()
        print(f"MessageServer: Подключен к Redis ({REDIS_URL})")
    except Exception as e:
        print(f"MessageServer: Ошибка подключения к Redis: {e}")
        raise
    yield
    for ws in connections.values():
        try:
            await ws.close()
        except:
            pass
    if redis_pool:
        await redis_pool.close()

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
            print(f"KDS: Bundle uploaded for {username}")
    except Exception as e:
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
            return resp.json()
    except Exception as e:
        print(f"KDS get bundle error: {e}")
        raise

async def store_message(recipient: str, message: dict):
    await redis_pool.rpush(f"queue:{recipient}", json.dumps(message))

async def deliver_offline_messages(username: str, websocket: WebSocket):
    key = f"queue:{username}"
    while True:
        msg_json = await redis_pool.lpop(key)
        if msg_json is None:
            break
        msg = json.loads(msg_json)
        await websocket.send_json(msg)

@app.get("/health")
async def health():
    return {"status": "ok"}

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    print("New WebSocket connection attempt...")
    await ws.accept()
    print("WebSocket connection accepted")
    username = None
    auth_token = None

    try:
        while True:
            data = await ws.receive_text()
            msg = json.loads(data)
            msg_type = msg.get("type")
            print(f"Received message type: {msg_type} from {msg.get('username', 'unknown')}")

           

            if msg_type == "register":
                username = msg.get("username")
                password = msg.get("password")
                if not username or not password:
                    await ws.send_json({"type": "error", "message": "Username and password required"})
                    continue
                exists = await redis_pool.hexists(f"user:{username}", "password_hash")
                if exists:
                    await ws.send_json({"type": "error", "message": "User already exists"})
                    continue
                key, salt = pbkdf2_hash(password)
                await redis_pool.hset(f"user:{username}", mapping={
                    "password_hash": base64.b64encode(key).decode(),
                    "salt": base64.b64encode(salt).decode()
                })
                # Если есть бандл - загружаем, если нет - просто регистрируем
                bundle = msg.get("bundle")
                if bundle:
                    try:
                        await kds_upload_bundle(username, bundle)
                    except Exception as e:
                        print(f"Bundle upload error: {e}")
                
                print(f"User {username} registered successfully")
                await ws.send_json({"type": "register", "status": "ok"})

            elif msg_type == "login":
                username = msg.get("username")
                password = msg.get("password")
                if not username or not password:
                    await ws.send_json({"type": "error", "message": "Invalid credentials"})
                    continue
                user_data = await redis_pool.hgetall(f"user:{username}")
                if not user_data:
                    await ws.send_json({"type": "error", "message": "Invalid credentials"})
                    continue
                stored_hash = base64.b64decode(user_data["password_hash"])
                salt = base64.b64decode(user_data["salt"])
                test_key, _ = pbkdf2_hash(password, salt)
                if test_key != stored_hash:
                    await ws.send_json({"type": "error", "message": "Invalid credentials"})
                    continue
                token = os.urandom(32).hex()
                await redis_pool.setex(f"token:{token}", 3600, username)
                auth_token = token
                connections[username] = ws
                print(f"User {username} logged in")
                await ws.send_json({"type": "login", "status": "ok", "token": token})
                await deliver_offline_messages(username, ws)

            elif msg_type == "get_bundle":
                if not auth_token:
                    await ws.send_json({"type": "error", "message": "Not authenticated"})
                    continue
                target = msg.get("username")
                if not target:
                    await ws.send_json({"type": "error", "message": "Username required"})
                    continue
                try:
                    bundle = await kds_get_bundle(target)
                    await ws.send_json({"type": "bundle", "username": target, "bundle": bundle})
                except Exception as e:
                    await ws.send_json({"type": "error", "message": f"User bundle not found: {str(e)}"})

            elif msg_type == "send":
                if not auth_token:
                    await ws.send_json({"type": "error", "message": "Not authenticated"})
                    continue
                recipient = msg.get("recipient")
                message_payload = msg.get("message")
                if not recipient or not message_payload:
                    await ws.send_json({"type": "error", "message": "Recipient and message required"})
                    continue
                
                # ОТЛАДКА
                print(f"DEBUG: Sending to {recipient}, payload type: {message_payload.get('type')}")
                print(f"DEBUG: Payload keys: {list(message_payload.keys())}")
                
                if recipient in connections:
                    await connections[recipient].send_json({
                        "type": "message",
                        "sender": username,
                        "data": message_payload
                    })
                    print(f"Message sent from {username} to online user {recipient}")
                else:
                    await store_message(recipient, {
                        "type": "message",
                        "sender": username,
                        "data": message_payload
                    })
                    print(f"Message from {username} to {recipient} stored offline")
                await ws.send_json({"type": "ack", "status": "sent"})

            elif msg_type == "logout":
                print(f"User {username} logging out")
                break

            else:
                await ws.send_json({"type": "error", "message": f"Unknown message type: {msg_type}"})

    except WebSocketDisconnect:
        print(f"Client {username} disconnected")
    except Exception as e:
        print(f"WebSocket error for {username}: {e}")
    finally:
        if username and username in connections:
            del connections[username]
            print(f"Removed {username} from connections")
        if auth_token:
            await redis_pool.delete(f"token:{auth_token}")