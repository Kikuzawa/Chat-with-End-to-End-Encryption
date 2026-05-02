"""
Тесты X3DH согласования ключей и двустороннего обмена через Double Ratchet.

Тест охватывает:
  1. Полный X3DH-рукопожатие между Alice и Bob.
  2. Alice → Bob: первое сообщение (prekey), расшифровка Bob'ом.
  3. Bob → Alice: ответ, расшифровка Alice (DH-шаговое обновление).
  4. Множественный обмен с чередованием сторон.
  5. Верификацию подписи SPK (initiate_session должна падать при неверной подписи).
"""
import pytest
import base64
import os
import nacl.signing

from crypto.keymanager import KeyManager
from crypto.sessionmanager import SessionManager


def make_bob():
    """Создаёт KeyManager Bob'а со всеми ключами."""
    km = KeyManager()
    km.generate_identity_key()
    km.generate_spk()
    km.generate_opks(3)
    return km


def make_alice():
    """Создаёт KeyManager Alice (только identity key)."""
    km = KeyManager()
    km.generate_identity_key()
    return km


def init_session(alice_km, bob_km, use_opk: bool = False):
    """Вспомогательная функция: полное X3DH согласование."""
    bob_bundle = bob_km.export_bundle()

    if use_opk and bob_km.opks:
        opk_idx = 0
        opk_pub = bob_km.opks[opk_idx][1]
        bob_bundle["opk"] = {"public": base64.b64encode(opk_pub).decode()}
        opk_priv_dict = {opk_idx: bob_km.opks[opk_idx][0]}
        used_opk_id = opk_idx
    else:
        opk_priv_dict = {}
        used_opk_id = None

    alice_state, ek_pub, _ = SessionManager.initiate_session(
        alice_km.ik_x25519_priv, alice_km.ik_x25519_pub,
        bob_bundle, used_opk_id
    )
    bob_state = SessionManager.receive_session(
        bob_km.ik_x25519_priv, bob_km.ik_x25519_pub,
        bob_km.spk_priv, bob_km.spk_pub,
        opk_priv_dict,
        alice_km.ik_x25519_pub, ek_pub, used_opk_id
    )
    return alice_state, bob_state, ek_pub


# ── Тесты ─────────────────────────────────────────────────────────────────────

def test_alice_to_bob_first_message():
    """Alice шифрует первое сообщение, Bob расшифровывает."""
    alice_km, bob_km = make_alice(), make_bob()
    alice_state, bob_state, _ = init_session(alice_km, bob_km)

    plaintext = b"hello Bob"
    ct, hdr = SessionManager.encrypt_for_session(alice_state, plaintext)
    decrypted = SessionManager.decrypt_from_session(bob_state, ct, hdr)
    assert decrypted == plaintext


def test_bob_replies_to_alice():
    """Bob отвечает, Alice расшифровывает (DH-шаговое обновление у Alice)."""
    alice_km, bob_km = make_alice(), make_bob()
    alice_state, bob_state, _ = init_session(alice_km, bob_km)

    # Alice → Bob
    ct1, hdr1 = SessionManager.encrypt_for_session(alice_state, b"ping")
    SessionManager.decrypt_from_session(bob_state, ct1, hdr1)

    # Bob → Alice (новый DH pub Bob'а триггерит рэтчет у Alice)
    ct2, hdr2 = SessionManager.encrypt_for_session(bob_state, b"pong")
    decrypted = SessionManager.decrypt_from_session(alice_state, ct2, hdr2)
    assert decrypted == b"pong"


def test_multiple_messages_alternating():
    """Чередующийся обмен несколькими сообщениями."""
    alice_km, bob_km = make_alice(), make_bob()
    alice_state, bob_state, _ = init_session(alice_km, bob_km)

    messages = [
        (alice_state, bob_state,   b"msg A1"),
        (alice_state, bob_state,   b"msg A2"),
        (bob_state,   alice_state, b"msg B1"),
        (alice_state, bob_state,   b"msg A3"),
        (bob_state,   alice_state, b"msg B2"),
        (bob_state,   alice_state, b"msg B3"),
    ]
    for sender, receiver, text in messages:
        ct, hdr = SessionManager.encrypt_for_session(sender, text)
        assert SessionManager.decrypt_from_session(receiver, ct, hdr) == text


def test_x3dh_with_opk():
    """X3DH с использованием одноразового предключа (OPK)."""
    alice_km, bob_km = make_alice(), make_bob()
    alice_state, bob_state, _ = init_session(alice_km, bob_km, use_opk=True)

    pt = b"OPK test message"
    ct, hdr = SessionManager.encrypt_for_session(alice_state, pt)
    assert SessionManager.decrypt_from_session(bob_state, ct, hdr) == pt


def test_invalid_spk_signature_raises():
    """initiate_session должна отклонить бандл с неверной подписью SPK."""
    alice_km, bob_km = make_alice(), make_bob()
    bob_bundle = bob_km.export_bundle()

    # Подменяем SPK (MITM-атака)
    fake_priv = nacl.signing.SigningKey.generate()
    bad_sig = base64.b64encode(fake_priv.sign(b"fake").signature).decode()
    bob_bundle["spk_signature"] = bad_sig

    with pytest.raises(ValueError, match="подпись SPK"):
        SessionManager.initiate_session(
            alice_km.ik_x25519_priv, alice_km.ik_x25519_pub,
            bob_bundle, None
        )


def test_replay_attack_rejected():
    """Повторная отправка того же шифртекста должна быть отклонена."""
    alice_km, bob_km = make_alice(), make_bob()
    alice_state, bob_state, _ = init_session(alice_km, bob_km)

    ct, hdr = SessionManager.encrypt_for_session(alice_state, b"once only")
    SessionManager.decrypt_from_session(bob_state, ct, hdr)

    with pytest.raises(ValueError, match="replay"):
        SessionManager.decrypt_from_session(bob_state, ct, hdr)


def test_forward_secrecy_different_keys():
    """Каждое сообщение шифруется уникальным ключом (разные шифртексты)."""
    alice_km, bob_km = make_alice(), make_bob()
    alice_state, bob_state, _ = init_session(alice_km, bob_km)

    ct1, _ = SessionManager.encrypt_for_session(alice_state, b"same text")
    ct2, _ = SessionManager.encrypt_for_session(alice_state, b"same text")
    # Разные message keys → разные шифртексты
    assert ct1 != ct2
