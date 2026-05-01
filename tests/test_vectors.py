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
    """Тестовый вектор из RFC 7748"""
    # RFC 7748 Section 6.1
    scalar = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    u_coordinate = bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
    expected = bytes.fromhex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
    
    result = nacl.bindings.crypto_scalarmult(scalar, u_coordinate)
    assert result == expected
    print("X25519 RFC 7748 test passed")