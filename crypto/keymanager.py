"""
KeyManager – генерация и управление ключами пользователя (стр. 15).
"""
import os
import sys
import json
import base64
import nacl.bindings
import nacl.signing
import nacl.encoding
from datetime import datetime
import config

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from log_utils import get_file_logger, h, SEP, SEP2

_log = get_file_logger("keymanager", "crypto.log")


class KeyManager:
    def __init__(self, storage_path=None):
        self.storage_path = storage_path or os.path.join(config.KEY_DIR, "keys.json")
        self.username = None
        self.ik_x25519_priv = None
        self.ik_x25519_pub = None
        self.ik_ed25519_sign = None
        self.ik_ed25519_verify = None
        self.spk_priv = None
        self.spk_pub = None
        self.spk_signature = None
        self.spk_timestamp = None
        self.opks = []

    def generate_identity_key(self):
        """Создаёт долговременную идентификационную пару (X25519) и Ed25519."""
        _log.info(SEP)
        _log.info("[KEYMANAGER/GEN/IK] ▶ СТАРТ  Генерация Identity Key (IK)")
        _log.info("[KEYMANAGER/GEN/IK]   Алгоритм X25519 + Ed25519")

        # X25519 ключи (используем правильный API для PyNaCl 1.5+)
        seed_x = os.urandom(32)
        self.ik_x25519_priv = nacl.bindings.crypto_box_seed_keypair(seed_x)[0]
        self.ik_x25519_pub = nacl.bindings.crypto_scalarmult_base(self.ik_x25519_priv)

        _log.info(f"[KEYMANAGER/GEN/IK]   IK_x25519_priv = {h(self.ik_x25519_priv)}")
        _log.info(f"[KEYMANAGER/GEN/IK]   IK_x25519_pub  = {h(self.ik_x25519_pub)}")

        # Ed25519 для подписей
        seed = os.urandom(32)
        self.ik_ed25519_sign = nacl.signing.SigningKey(seed)
        self.ik_ed25519_verify = self.ik_ed25519_sign.verify_key

        _log.info(f"[KEYMANAGER/GEN/IK]   IK_ed25519_vk  = {h(bytes(self.ik_ed25519_verify))}")
        _log.info("[KEYMANAGER/GEN/IK] ✓ ГОТОВО  Identity Key сгенерирован")

    def generate_spk(self):
        """Генерирует подписанный предключ (SPK) Curve25519."""
        _log.info(SEP)
        _log.info("[KEYMANAGER/GEN/SPK] ▶ СТАРТ  Генерация Signed PreKey (SPK)")
        _log.info("[KEYMANAGER/GEN/SPK]   Алгоритм X25519, подпись Ed25519")

        self.spk_priv = nacl.bindings.crypto_box_seed_keypair(os.urandom(32))[0]
        self.spk_pub = nacl.bindings.crypto_scalarmult_base(self.spk_priv)
        self.spk_timestamp = datetime.utcnow().isoformat()
        message = self.spk_pub + self.spk_timestamp.encode()
        self.spk_signature = self.ik_ed25519_sign.sign(message).signature

        _log.info(f"[KEYMANAGER/GEN/SPK]   SPK_priv      = {h(self.spk_priv)}")
        _log.info(f"[KEYMANAGER/GEN/SPK]   SPK_pub       = {h(self.spk_pub)}")
        _log.info(f"[KEYMANAGER/GEN/SPK]   SPK_timestamp = {self.spk_timestamp}")
        _log.info(f"[KEYMANAGER/GEN/SPK]   SPK_signature = {h(self.spk_signature)}")
        _log.info("[KEYMANAGER/GEN/SPK] ✓ ГОТОВО  SPK сгенерирован и подписан IK_ed25519")

    def generate_opks(self, count=None):
        """Создаёт пул одноразовых предключей (OPK)."""
        if count is None:
            count = config.PREKEY_POOL_SIZE
        _log.info(SEP)
        _log.info(f"[KEYMANAGER/GEN/OPK] ▶ СТАРТ  Генерация {count} OPK (One-Time PreKeys)")

        self.opks = []
        for i in range(count):
            priv = nacl.bindings.crypto_box_seed_keypair(os.urandom(32))[0]
            pub = nacl.bindings.crypto_scalarmult_base(priv)
            self.opks.append((priv, pub))
            _log.info(f"[KEYMANAGER/GEN/OPK]   OPK[{i:02d}] pub = {h(pub)}")

        _log.info(f"[KEYMANAGER/GEN/OPK] ✓ ГОТОВО  Сгенерировано {count} OPK")

    def export_bundle(self) -> dict:
        """Экспорт открытых данных для KDS (стр. 19)."""
        return {
            "username": self.username,
            "ik_x25519": base64.b64encode(self.ik_x25519_pub).decode(),
            "ik_ed25519": base64.b64encode(bytes(self.ik_ed25519_verify)).decode(),
            "spk": base64.b64encode(self.spk_pub).decode(),
            "spk_signature": base64.b64encode(self.spk_signature).decode(),
            "spk_timestamp": self.spk_timestamp,
            "opks": [base64.b64encode(opk[1]).decode() for opk in self.opks]
        }

    def save_keys(self, username: str):
        """Сохраняет ключи в JSON-файл."""
        self.username = username
        _log.info(SEP)
        _log.info(f"[KEYMANAGER/SAVE] ▶ СТАРТ  Сохранение ключей для '{username}'")
        _log.info(f"[KEYMANAGER/SAVE]   Путь: {self.storage_path}")

        data = {
            "username": username,
            "ik_x25519_priv": base64.b64encode(self.ik_x25519_priv).decode(),
            "ik_x25519_pub": base64.b64encode(self.ik_x25519_pub).decode(),
            "ik_ed25519_seed": base64.b64encode(bytes(self.ik_ed25519_sign._seed)).decode(),
            "spk_priv": base64.b64encode(self.spk_priv).decode(),
            "spk_pub": base64.b64encode(self.spk_pub).decode(),
            "spk_signature": base64.b64encode(self.spk_signature).decode(),
            "spk_timestamp": self.spk_timestamp,
            "opks": [(base64.b64encode(priv).decode(), base64.b64encode(pub).decode()) for priv, pub in self.opks]
        }
        os.makedirs(os.path.dirname(self.storage_path), exist_ok=True)
        with open(self.storage_path, 'w') as f:
            json.dump(data, f, indent=2)

        _log.info(f"[KEYMANAGER/SAVE]   IK_x25519_pub = {h(self.ik_x25519_pub)}")
        _log.info(f"[KEYMANAGER/SAVE]   SPK_pub       = {h(self.spk_pub)}")
        _log.info(f"[KEYMANAGER/SAVE]   OPK count     = {len(self.opks)}")
        _log.info(f"[KEYMANAGER/SAVE] ✓ ГОТОВО  Ключи записаны в файл")
        print(f"Ключи сохранены в {self.storage_path}")

    @classmethod
    def load_keys(cls, storage_path=None) -> 'KeyManager':
        """Загружает ключи из файла."""
        km = cls(storage_path)
        _log.info(SEP)
        _log.info(f"[KEYMANAGER/LOAD] ▶ СТАРТ  Загрузка ключей из файла")
        _log.info(f"[KEYMANAGER/LOAD]   Путь: {km.storage_path}")

        with open(km.storage_path, 'r') as f:
            data = json.load(f)

        km.username = data["username"]
        km.ik_x25519_priv = base64.b64decode(data["ik_x25519_priv"])
        km.ik_x25519_pub = base64.b64decode(data["ik_x25519_pub"])
        km.ik_ed25519_sign = nacl.signing.SigningKey(base64.b64decode(data["ik_ed25519_seed"]))
        km.ik_ed25519_verify = km.ik_ed25519_sign.verify_key
        km.spk_priv = base64.b64decode(data["spk_priv"])
        km.spk_pub = base64.b64decode(data["spk_pub"])
        km.spk_signature = base64.b64decode(data["spk_signature"])
        km.spk_timestamp = data["spk_timestamp"]
        km.opks = [(base64.b64decode(priv), base64.b64decode(pub)) for priv, pub in data["opks"]]

        _log.info(f"[KEYMANAGER/LOAD]   username      = {km.username}")
        _log.info(f"[KEYMANAGER/LOAD]   IK_x25519_pub = {h(km.ik_x25519_pub)}")
        _log.info(f"[KEYMANAGER/LOAD]   SPK_pub       = {h(km.spk_pub)}")
        _log.info(f"[KEYMANAGER/LOAD]   OPK count     = {len(km.opks)}")
        _log.info(f"[KEYMANAGER/LOAD] ✓ ГОТОВО  Ключи загружены из файла")
        return km
