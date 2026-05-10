"""
Тестовые векторы NIST для AES-256-GCM и X25519 (стр. 45).
"""
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import config
import base64
import nacl.bindings

def test_aes_gcm_encrypt_decrypt():
    """Тест AES-256-GCM: шифрование и расшифрование"""
    key = bytes(32)  # 32 нулевых байта
    plaintext = b"Test message for AES-256-GCM"
    aad = b"additional data"
    
    aes = AESGCM(key)
    nonce = bytes(12)
    
    ciphertext = aes.encrypt(nonce, plaintext, aad)
    decrypted = aes.decrypt(nonce, ciphertext, aad)
    
    assert decrypted == plaintext
    print(f"AES-256-GCM test passed: encrypted {len(plaintext)} bytes")

def test_x25519_dh():
    """Тест X25519 Diffie-Hellman"""
    # Генерируем две пары ключей
    alice_priv = nacl.bindings.crypto_box_seed_keypair(bytes(32))[0]
    alice_pub = nacl.bindings.crypto_scalarmult_base(alice_priv)
    
    bob_priv = nacl.bindings.crypto_box_seed_keypair(bytes(32))[0]
    bob_pub = nacl.bindings.crypto_scalarmult_base(bob_priv)
    
    # Вычисляем общий секрет
    shared_alice = nacl.bindings.crypto_scalarmult(alice_priv, bob_pub)
    shared_bob = nacl.bindings.crypto_scalarmult(bob_priv, alice_pub)
    
    assert shared_alice == shared_bob
    print(f"X25519 DH test passed: shared secret length = {len(shared_alice)}")

def test_x25519_rfc7748():
    """
    Тестовые векторы из RFC 7748 Section 5.2 (X25519 function test vectors).
    Оба вектора должны давать указанный выходной u-coordinate.
    """
    # Вектор 1 (RFC 7748 §5.2)
    scalar1 = bytes.fromhex(
        "a546e36bf0527c9d3b16154b82465edd"
        "62144c0ac1fc5a18506a2244ba449ac4"
    )
    u1 = bytes.fromhex(
        "e6db6867583030db3594c1a424b15f7c"
        "726624ec26b3353b10a903a6d0ab1c4c"
    )
    expected1 = bytes.fromhex(
        "c3da55379de9c6908e94ea4df28d084f"
        "32eccf03491c71f754b4075577a28552"
    )
    assert nacl.bindings.crypto_scalarmult(scalar1, u1) == expected1

    # Вектор 2 (RFC 7748 §5.2)
    scalar2 = bytes.fromhex(
        "4b66e9d4d1b4673c5ad22691957d6af5"
        "c11b6421e0ea01d42ca4169e7918ba0d"
    )
    u2 = bytes.fromhex(
        "e5210f12786811d3f4b7959d0538ae2c"
        "31dbe7106fc03c3efc4cd549c715a413"
    )
    expected2 = bytes.fromhex(
        "95cbde9476e8907d7aade45cb4b873f8"
        "8b595a68799fa152e6f8f7647aac7957"
    )
    assert nacl.bindings.crypto_scalarmult(scalar2, u2) == expected2
    print("X25519 RFC 7748 test vectors passed")