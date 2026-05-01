"""
KeyManager – генерация и управление ключами пользователя (стр. 15).
"""
import os
import json
import base64
import nacl.bindings
import nacl.signing
import nacl.encoding
from datetime import datetime
import config

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
        # X25519 ключи (используем правильный API для PyNaCl 1.5+)
        self.ik_x25519_priv = nacl.bindings.crypto_box_seed_keypair(os.urandom(32))[0]
        self.ik_x25519_pub = nacl.bindings.crypto_scalarmult_base(self.ik_x25519_priv)
        
        # Ed25519 для подписей
        seed = os.urandom(32)
        self.ik_ed25519_sign = nacl.signing.SigningKey(seed)
        self.ik_ed25519_verify = self.ik_ed25519_sign.verify_key

    def generate_spk(self):
        """Генерирует подписанный предключ (SPK) Curve25519."""
        self.spk_priv = nacl.bindings.crypto_box_seed_keypair(os.urandom(32))[0]
        self.spk_pub = nacl.bindings.crypto_scalarmult_base(self.spk_priv)
        self.spk_timestamp = datetime.utcnow().isoformat()
        message = self.spk_pub + self.spk_timestamp.encode()
        self.spk_signature = self.ik_ed25519_sign.sign(message).signature

    def generate_opks(self, count=None):
        """Создаёт пул одноразовых предключей (OPK)."""
        if count is None:
            count = config.PREKEY_POOL_SIZE
        self.opks = []
        for _ in range(count):
            priv = nacl.bindings.crypto_box_seed_keypair(os.urandom(32))[0]
            pub = nacl.bindings.crypto_scalarmult_base(priv)
            self.opks.append((priv, pub))

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
        print(f"Ключи сохранены в {self.storage_path}")

    @classmethod
    def load_keys(cls, storage_path=None) -> 'KeyManager':
        """Загружает ключи из файла."""
        km = cls(storage_path)
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
        return km