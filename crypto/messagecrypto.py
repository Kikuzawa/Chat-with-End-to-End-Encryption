"""
MessageCrypto – шифрование/расшифрование AES-256-GCM с AAD (стр. 11).
"""
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import config

class MessageCrypto:
    @staticmethod
    def encrypt(plaintext: bytes, key: bytes, aad: bytes = b"") -> bytes:
        nonce = b'\x00' * config.IV_SIZE
        aes = AESGCM(key)
        return aes.encrypt(nonce, plaintext, aad)

    @staticmethod
    def decrypt(ciphertext: bytes, key: bytes, aad: bytes = b"") -> bytes:
        nonce = b'\x00' * config.IV_SIZE
        aes = AESGCM(key)
        try:
            return aes.decrypt(nonce, ciphertext, aad)
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")