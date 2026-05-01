import asyncio
import json
import websockets

async def test_server():
    # Подключаемся
    ws = await websockets.connect("ws://localhost:8000/ws")
    print("1. Подключены к серверу")
    
    # Регистрируем test1
    await ws.send(json.dumps({
        "type": "register",
        "username": "test1",
        "password": "test1"
    }))
    resp = await ws.recv()
    print(f"2. Регистрация test1: {resp}")
    
    await ws.close()
    
    # Подключаем test2
    ws = await websockets.connect("ws://localhost:8000/ws")
    await ws.send(json.dumps({
        "type": "register",
        "username": "test2",
        "password": "test2"
    }))
    resp = await ws.recv()
    print(f"3. Регистрация test2: {resp}")
    await ws.close()
    
    # Логинимся как test1
    ws = await websockets.connect("ws://localhost:8000/ws")
    await ws.send(json.dumps({
        "type": "login",
        "username": "test1",
        "password": "test1"
    }))
    resp = await ws.recv()
    print(f"4. Логин test1: {resp}")
    
    # Логинимся как test2 (второе соединение)
    ws2 = await websockets.connect("ws://localhost:8000/ws")
    await ws2.send(json.dumps({
        "type": "login",
        "username": "test2",
        "password": "test2"
    }))
    resp = await ws2.recv()
    print(f"5. Логин test2: {resp}")
    
    # test1 отправляет сообщение test2
    await ws.send(json.dumps({
        "type": "send",
        "recipient": "test2",
        "message": {
            "type": "message",
            "text": "Привет, test2!"
        }
    }))
    resp = await ws.recv()
    print(f"6. Отправка сообщения: {resp}")
    
    # test2 проверяет входящие
    try:
        resp = await asyncio.wait_for(ws2.recv(), timeout=2.0)
        print(f"7. test2 получил: {resp}")
    except asyncio.TimeoutError:
        print("7. test2 НЕ ПОЛУЧИЛ сообщение!")
    
    await ws.close()
    await ws2.close()

asyncio.run(test_server())
