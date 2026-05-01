"""
Тестовые векторы NIST для AES-256-GCM и X25519 (стр. 45).
"""
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import config
import base64
import nacl.bindings

# NIST CAVP test vectors for AES-256-GCM (частичный пример)
AES_GCM_VECTORS = [
    {
        "key": bytes.fromhex("92e11dcdaa866f5ce790fd24501f92509aacf4cb8b1339d50c9c1240935dd08b"),
        "iv": bytes.fromhex("ac93a1a6145299bde902f21a"),
        "pt": bytes.fromhex("2d71bcfa914e4ac045b2aa609c7a9e3158636b"),
        "aad": bytes.fromhex("1e0889016f67601c8ebea4943bc23ad6"),
        "ct": bytes.fromhex("8995ae2e6df3dbf96fac7b7137bae67f0f735019a9fce6e2"),
        "tag": bytes.fromhex("010759a2785aae301ee55b143e3d335c")
    }
]

def test_aes_gcm_vector():
    for vec in AES_GCM_VECTORS:
        aes = AESGCM(vec["key"])
        nonce = vec["iv"]
        ct = aes.encrypt(nonce, vec["pt"], vec["aad"])
        assert ct == vec["ct"] + vec["tag"]
        dec = aes.decrypt(nonce, ct, vec["aad"])
        assert dec == vec["pt"]

# Тестовый вектор X25519 из RFC 7748 (Section 6.1)
def test_x25519():
    scalar = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    u = bytes.fromhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    expected = bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    result = nacl.bindings.crypto_scalarmult(scalar, u)
    assert result == expected