"""
Тесты MessageCrypto (AES-256-GCM с случайным nonce).

Проверяемые свойства:
  - Корректное шифрование/расшифрование
  - Случайность nonce: два вызова encrypt дают разный шифртекст
  - Нарушение AAD вызывает ошибку расшифровки
  - Неверный ключ вызывает ошибку расшифровки
  - Нарушение целостности (модификация шифртекста) вызывает ошибку
  - Нарушение nonce вызывает ошибку
  - Формат: первые 12 байт – nonce, остальное – ciphertext+tag
"""
import os
import pytest
from crypto.messagecrypto import MessageCrypto
import config


KEY = os.urandom(32)
PLAINTEXT = b"Secret message for AES-256-GCM test"
AAD = b"additional authenticated data"


class TestEncryptDecrypt:
    def test_basic_roundtrip(self):
        ct = MessageCrypto.encrypt(PLAINTEXT, KEY)
        pt = MessageCrypto.decrypt(ct, KEY)
        assert pt == PLAINTEXT

    def test_roundtrip_with_aad(self):
        ct = MessageCrypto.encrypt(PLAINTEXT, KEY, AAD)
        pt = MessageCrypto.decrypt(ct, KEY, AAD)
        assert pt == PLAINTEXT

    def test_empty_plaintext(self):
        ct = MessageCrypto.encrypt(b"", KEY)
        pt = MessageCrypto.decrypt(ct, KEY)
        assert pt == b""

    def test_nonce_is_random(self):
        """Два шифрования одного текста дают разный шифртекст (разные nonce)."""
        ct1 = MessageCrypto.encrypt(PLAINTEXT, KEY)
        ct2 = MessageCrypto.encrypt(PLAINTEXT, KEY)
        assert ct1 != ct2

    def test_nonce_prepended(self):
        """Первые IV_SIZE байт — nonce, остаток — AES-GCM шифртекст+тег."""
        ct = MessageCrypto.encrypt(PLAINTEXT, KEY)
        assert len(ct) == config.IV_SIZE + len(PLAINTEXT) + config.TAG_SIZE

    def test_different_keys_different_ciphertext(self):
        key2 = os.urandom(32)
        ct1 = MessageCrypto.encrypt(PLAINTEXT, KEY)
        ct2 = MessageCrypto.encrypt(PLAINTEXT, key2)
        # Разные ключи → разные шифртексты (с подавляющей вероятностью)
        assert ct1[config.IV_SIZE:] != ct2[config.IV_SIZE:]


class TestDecryptFailures:
    def test_wrong_key_raises(self):
        ct = MessageCrypto.encrypt(PLAINTEXT, KEY)
        wrong_key = os.urandom(32)
        with pytest.raises(ValueError, match="Decryption failed"):
            MessageCrypto.decrypt(ct, wrong_key)

    def test_wrong_aad_raises(self):
        ct = MessageCrypto.encrypt(PLAINTEXT, KEY, AAD)
        with pytest.raises(ValueError, match="Decryption failed"):
            MessageCrypto.decrypt(ct, KEY, b"wrong aad")

    def test_missing_aad_raises(self):
        ct = MessageCrypto.encrypt(PLAINTEXT, KEY, AAD)
        with pytest.raises(ValueError, match="Decryption failed"):
            MessageCrypto.decrypt(ct, KEY)  # AAD не передан

    def test_corrupted_ciphertext_raises(self):
        ct = bytearray(MessageCrypto.encrypt(PLAINTEXT, KEY))
        ct[-1] ^= 0xFF  # портим последний байт тега
        with pytest.raises(ValueError, match="Decryption failed"):
            MessageCrypto.decrypt(bytes(ct), KEY)

    def test_corrupted_nonce_raises(self):
        ct = bytearray(MessageCrypto.encrypt(PLAINTEXT, KEY))
        ct[0] ^= 0xFF  # портим nonce
        with pytest.raises(ValueError, match="Decryption failed"):
            MessageCrypto.decrypt(bytes(ct), KEY)

    def test_too_short_data_raises(self):
        with pytest.raises(ValueError, match="Слишком короткий"):
            MessageCrypto.decrypt(b"\x00" * 5, KEY)
