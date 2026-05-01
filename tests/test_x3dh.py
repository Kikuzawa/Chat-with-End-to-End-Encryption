"""Тест согласования ключей по X3DH между двумя сторонами."""
import pytest
from crypto.keymanager import KeyManager
from crypto.sessionmanager import SessionManager
import base64
import os

def test_x3dh_handshake():
    # Алиса и Боб
    alice_km = KeyManager()
    alice_km.generate_identity_key()
    bob_km = KeyManager()
    bob_km.generate_identity_key()
    bob_km.generate_spk()
    bob_km.generate_opks(3)
    
    # Боб публикует пучок
    bob_bundle = bob_km.export_bundle()
    
    # Алиса инициирует сессию с использованием OPK
    opk_used_index = 0
    opk_pub = bob_km.opks[opk_used_index][1]
    bob_bundle["opk"] = {"public": base64.b64encode(opk_pub).decode()}

    alice_state, ek_pub, _ = SessionManager.initiate_session(
        alice_km.ik_x25519_priv, alice_km.ik_x25519_pub, bob_bundle, opk_used_index
    )
    
    # Боб принимает сессию
    opk_priv_dict = {opk_used_index: bob_km.opks[opk_used_index][0]}
    bob_state = SessionManager.receive_session(
        bob_km.ik_x25519_priv, bob_km.ik_x25519_pub,
        bob_km.spk_priv, bob_km.spk_pub,
        opk_priv_dict,
        alice_km.ik_x25519_pub, ek_pub, opk_used_index
    )
    
    # Проверяем, что корневые ключи совпадают
    assert alice_state.root_key == bob_state.root_key
    
    # Шифруем сообщение от Алисы и расшифровываем Бобом
    plain = b"hello Bob"
    ciphertext, header = SessionManager.encrypt_for_session(alice_state, plain)
    decrypted = SessionManager.decrypt_from_session(bob_state, ciphertext, header)
    assert decrypted == plain