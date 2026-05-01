"""
KDS – Сервис распространения ключей (Key Distribution Server), стр. 30.
"""
import asyncio
import json
import sys
import os
from fastapi import FastAPI, HTTPException, Depends, Request
from pydantic import BaseModel

# Добавляем корень проекта в путь
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import redis.asyncio as aioredis
except ImportError:
    import aioredis

import base64
from config import REDIS_URL, KDS_API_KEY

app = FastAPI(title="KDS")

class BundleUpload(BaseModel):
    username: str
    ik_x25519: str
    ik_ed25519: str
    spk: str
    spk_signature: str
    spk_timestamp: str
    opks: list[str]

# Глобальная переменная для Redis
redis_client = None

@app.on_event("startup")
async def startup():
    global redis_client
    try:
        redis_url = os.getenv("REDIS_URL", "redis://redis:6379")
        print(f"KDS: Connecting to Redis at {redis_url}")
        redis_client = await aioredis.from_url(redis_url, decode_responses=True)
        await redis_client.ping()
        print("KDS: Connected to Redis successfully")
    except Exception as e:
        print(f"KDS: Error connecting to Redis: {e}")
        raise

@app.on_event("shutdown")
async def shutdown():
    global redis_client
    if redis_client:
        await redis_client.close()

def verify_api_key(request: Request):
    key = request.headers.get("X-API-Key")
    expected_key = os.getenv("KDS_API_KEY", "internal-secret-key")
    if key != expected_key:
        raise HTTPException(403, "Invalid API Key")

@app.post("/users/{username}/bundle", dependencies=[Depends(verify_api_key)])
async def upload_bundle(username: str, bundle: BundleUpload):
    """Загрузка пакета предключей (стр. 31)."""
    key = f"user:{username}:bundle"
    
    # Сохраняем OPK как JSON строку в хеше
    opks_json = json.dumps(bundle.opks)
    
    data = {
        "ik_x25519": bundle.ik_x25519,
        "ik_ed25519": bundle.ik_ed25519,
        "spk": bundle.spk,
        "spk_signature": bundle.spk_signature,
        "spk_timestamp": bundle.spk_timestamp,
        "opks": opks_json  # Сохраняем как JSON строку
    }
    
    await redis_client.hset(key, mapping=data)
    
    # Также сохраняем OPK в отдельный set для быстрого извлечения
    if bundle.opks:
        await redis_client.delete(f"user:{username}:opks")  # Очищаем старые
        await redis_client.sadd(f"user:{username}:opks", *bundle.opks)
    
    print(f"KDS: Bundle stored for user {username} with {len(bundle.opks)} OPKs")
    return {"status": "ok"}

@app.get("/users/{username}/bundle", dependencies=[Depends(verify_api_key)])
async def get_bundle(username: str):
    """Получение пакета предключей с удалением одного OPK (стр. 32)."""
    key = f"user:{username}:bundle"
    exists = await redis_client.exists(key)
    if not exists:
        raise HTTPException(404, "User not found")
    
    data = await redis_client.hgetall(key)
    
    # Парсим OPK из JSON
    opks_list = json.loads(data.get("opks", "[]"))
    
    opk = None
    # Извлекаем один предключ из set
    opk_pop = await redis_client.spop(f"user:{username}:opks")
    if opk_pop:
        opk = {"public": opk_pop}
        print(f"KDS: Popped OPK for {username}")
    else:
        print(f"KDS: No OPKs available for {username}")
    
    result = {
        "ik_x25519": data.get("ik_x25519", ""),
        "ik_ed25519": data.get("ik_ed25519", ""),
        "spk": data.get("spk", ""),
        "spk_signature": data.get("spk_signature", ""),
        "spk_timestamp": data.get("spk_timestamp", ""),
        "opk": opk
    }
    
    return result

@app.get("/health")
async def health():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)