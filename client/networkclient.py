"""
NetworkClient – WebSocket клиент, общается с MessageServer (стр. 35).
"""
import asyncio
import json
import websockets
from typing import Optional, Callable

class NetworkClient:
    def __init__(self, server_url: str):
        self.server_url = server_url
        self.websocket = None
        self.token = None
        self.on_message_callback: Optional[Callable] = None
        self._listen_task = None
        self._response_queue = asyncio.Queue()
        self._is_listening = False

    async def connect(self):
        """Установка WebSocket соединения."""
        try:
            self.websocket = await websockets.connect(self.server_url, ping_interval=None)
            print(f"Подключено к {self.server_url}")
            # Запускаем фоновый приём сообщений
            self._listen_task = asyncio.create_task(self._message_dispatcher())
        except Exception as e:
            print(f"Ошибка подключения: {e}")
            raise

    async def send(self, data: dict):
        """Отправка JSON-сообщения."""
        if self.websocket:
            await self.websocket.send(json.dumps(data))
        else:
            raise ConnectionError("WebSocket не подключен")

    async def recv(self, timeout=5.0) -> dict:
        """Получение JSON-сообщения из очереди ответов."""
        try:
            return await asyncio.wait_for(self._response_queue.get(), timeout=timeout)
        except asyncio.TimeoutError:
            return {"type": "error", "message": "Timeout waiting for response"}

    async def close(self):
        """Закрытие соединения."""
        if self._listen_task:
            self._listen_task.cancel()
            try:
                await self._listen_task
            except asyncio.CancelledError:
                pass
        if self.websocket:
            await self.websocket.close()
            print("Соединение закрыто")

    async def login(self, username: str, password: str) -> bool:
        """Аутентификация пользователя."""
        await self.send({"type": "login", "username": username, "password": password})
        resp = await self.recv()
        if resp.get("status") == "ok":
            self.token = resp.get("token")
            self._is_listening = True
            return True
        print(f"Ошибка входа: {resp.get('message', 'Неизвестная ошибка')}")
        return False

    async def register(self, username: str, password: str, bundle: dict) -> bool:
        """Регистрация нового пользователя."""
        await self.send({
            "type": "register",
            "username": username,
            "password": password,
            "bundle": bundle
        })
        resp = await self.recv()
        if resp.get("status") == "ok":
            return True
        print(f"Ошибка регистрации: {resp.get('message', 'Неизвестная ошибка')}")
        return False

    async def get_bundle(self, username: str) -> Optional[dict]:
        """Получение пакета ключей пользователя."""
        await self.send({"type": "get_bundle", "username": username})
        resp = await self.recv()
        if resp.get("type") == "bundle":
            return resp["bundle"]
        print(f"Ошибка получения ключей: {resp}")
        return None

    async def send_message(self, recipient: str, message_data: dict):
        """Отправка зашифрованного сообщения."""
        await self.send({
            "type": "send",
            "recipient": recipient,
            "message": message_data
        })
        # Ждем подтверждения
        resp = await self.recv()
        return resp.get("status") == "sent"

    async def _message_dispatcher(self):
        """Фоновый диспетчер сообщений - разделяет ответы и входящие сообщения."""
        try:
            while True:
                msg = await self.websocket.recv()
                data = json.loads(msg)
                
                if data.get("type") == "message":
                    # Входящее сообщение - обрабатываем через callback
                    if self.on_message_callback:
                        await self.on_message_callback(data["sender"], data["data"])
                elif data.get("type") in ["ack", "bundle", "login", "register", "error"]:
                    # Ответ на запрос - кладем в очередь
                    await self._response_queue.put(data)
                else:
                    # Неизвестный тип - тоже в очередь
                    await self._response_queue.put(data)
                    
        except websockets.ConnectionClosed:
            print("Соединение с сервером разорвано")
        except asyncio.CancelledError:
            pass
        except Exception as e:
            print(f"Ошибка диспетчера: {e}")
            await self._response_queue.put({"type": "error", "message": str(e)})