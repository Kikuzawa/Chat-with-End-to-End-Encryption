"""
MessageCrypto – шифрование/расшифрование AES-256-GCM с AAD.
Формат шифртекста: nonce (12 байт) || ciphertext+tag
"""
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import config


class MessageCrypto:
    @staticmethod
    def encrypt(plaintext: bytes, key: bytes, aad: bytes = b"") -> bytes:
        """Шифрует plaintext ключом key. Возвращает nonce || ciphertext+tag."""
        nonce = os.urandom(config.IV_SIZE)
        aes = AESGCM(key)
        ciphertext = aes.encrypt(nonce, plaintext, aad)
        return nonce + ciphertext

    @staticmethod
    def decrypt(data: bytes, key: bytes, aad: bytes = b"") -> bytes:
        """Расшифровывает данные формата nonce(12) || ciphertext+tag."""
        if len(data) < config.IV_SIZE:
            raise ValueError("Слишком короткий шифртекст")
        nonce = data[:config.IV_SIZE]
        ciphertext = data[config.IV_SIZE:]
        aes = AESGCM(key)
        try:
            return aes.decrypt(nonce, ciphertext, aad)
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")
