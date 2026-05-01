"""
KDS – Сервис распространения ключей (Key Distribution Server).

Хранит публичные ключевые бандлы пользователей в Redis.
Доступен только во внутренней сети (защита API-ключом).
"""
import json
import os
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Depends, Request
from pydantic import BaseModel

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import redis.asyncio as aioredis
except ImportError:
    import aioredis

from config import REDIS_URL, KDS_API_KEY

redis_client = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global redis_client
    url = os.getenv("REDIS_URL", REDIS_URL)
    redis_client = await aioredis.from_url(url, decode_responses=True)
    await redis_client.ping()
    print(f"KDS: подключен к Redis ({url})")
    yield
    if redis_client:
        await redis_client.aclose()


app = FastAPI(title="KDS – Key Distribution Server", lifespan=lifespan)


class BundleUpload(BaseModel):
    username: str
    ik_x25519: str
    ik_ed25519: str
    spk: str
    spk_signature: str
    spk_timestamp: str
    opks: list[str]


def verify_api_key(request: Request):
    key = request.headers.get("X-API-Key")
    expected = os.getenv("KDS_API_KEY", KDS_API_KEY)
    if key != expected:
        raise HTTPException(status_code=403, detail="Invalid API Key")


@app.post("/users/{username}/bundle", dependencies=[Depends(verify_api_key)])
async def upload_bundle(username: str, bundle: BundleUpload):
    """Загрузка (или обновление) ключевого бандла пользователя."""
    key = f"user:{username}:bundle"
    await redis_client.hset(key, mapping={
        "ik_x25519":      bundle.ik_x25519,
        "ik_ed25519":     bundle.ik_ed25519,
        "spk":            bundle.spk,
        "spk_signature":  bundle.spk_signature,
        "spk_timestamp":  bundle.spk_timestamp,
        "opks":           json.dumps(bundle.opks),
    })
    # Одноразовые предключи хранятся отдельно (set) для атомарного spop
    if bundle.opks:
        await redis_client.delete(f"user:{username}:opks")
        await redis_client.sadd(f"user:{username}:opks", *bundle.opks)

    print(f"KDS: бандл сохранён для {username} ({len(bundle.opks)} OPK)")
    return {"status": "ok"}


@app.get("/users/{username}/bundle", dependencies=[Depends(verify_api_key)])
async def get_bundle(username: str):
    """
    Возвращает публичный бандл пользователя.
    Одновременно атомарно извлекает (и удаляет) один OPK из пула.
    """
    key = f"user:{username}:bundle"
    if not await redis_client.exists(key):
        raise HTTPException(status_code=404, detail=f"Пользователь {username} не найден")

    data = await redis_client.hgetall(key)

    # Предупреждение при исчерпании OPK
    opk = None
    opk_raw = await redis_client.spop(f"user:{username}:opks")
    if opk_raw:
        opk = {"public": opk_raw}
    else:
        remaining = 0
        print(f"KDS: OPK исчерпаны для {username}, сессия без OPK")

    return {
        "ik_x25519":     data.get("ik_x25519", ""),
        "ik_ed25519":    data.get("ik_ed25519", ""),
        "spk":           data.get("spk", ""),
        "spk_signature": data.get("spk_signature", ""),
        "spk_timestamp": data.get("spk_timestamp", ""),
        "opk":           opk,
    }


@app.get("/health")
async def health():
    return {"status": "healthy"}
