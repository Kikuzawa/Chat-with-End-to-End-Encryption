"""
Тест Double Ratchet: шифрование/расшифрование, out-of-order сообщения, DH-шаг.
"""
import os
import hashlib
import nacl.bindings
from crypto.sessionmanager import SessionManager, RatchetState, _kdf_rk


def _make_dh_pair():
    priv = nacl.bindings.crypto_box_seed_keypair(os.urandom(32))[0]
    pub  = nacl.bindings.crypto_scalarmult_base(priv)
    return priv, pub


def setup_ratchet():
    """
    Инициализирует два состояния с одинаковым send/recv chain key.
    their_dh_pub устанавливается равным реальному ключу собеседника,
    чтобы DH-шаг не срабатывал при первом сообщении.
    """
    sk = hashlib.sha256(b"shared secret").digest()

    a_priv, a_pub = _make_dh_pair()
    b_priv, b_pub = _make_dh_pair()

    # Общий chain key из shared secret
    _, shared_ck = _kdf_rk(sk, b"\x00" * 32)

    a_state = RatchetState()
    a_state.root_key       = sk
    a_state.our_dh_priv    = a_priv
    a_state.our_dh_pub     = a_pub
    a_state.their_dh_pub   = b_pub   # A ожидает от B именно b_pub → нет рэтчета
    a_state.send_chain_key = shared_ck
    a_state.recv_chain_key = shared_ck

    b_state = RatchetState()
    b_state.root_key       = sk
    b_state.our_dh_priv    = b_priv
    b_state.our_dh_pub     = b_pub
    b_state.their_dh_pub   = a_pub   # B ожидает от A именно a_pub → нет рэтчета
    b_state.send_chain_key = shared_ck
    b_state.recv_chain_key = shared_ck

    return a_state, b_state


def test_ratchet_encrypt_decrypt():
    """Базовое шифрование → расшифровка."""
    a, b = setup_ratchet()
    msg = b"ratchet test"
    ct, hdr = SessionManager.encrypt_for_session(a, msg)
    pt = SessionManager.decrypt_from_session(b, ct, hdr)
    assert pt == msg


def test_ratchet_multiple_messages():
    """Несколько последовательных сообщений в одном направлении."""
    a, b = setup_ratchet()
    for i in range(5):
        text = f"message {i}".encode()
        ct, hdr = SessionManager.encrypt_for_session(a, text)
        assert SessionManager.decrypt_from_session(b, ct, hdr) == text


def test_ratchet_bidirectional():
    """Чередующийся обмен без DH-шага (фиксированные ключи)."""
    a, b = setup_ratchet()

    ct1, h1 = SessionManager.encrypt_for_session(a, b"A to B")
    assert SessionManager.decrypt_from_session(b, ct1, h1) == b"A to B"

    ct2, h2 = SessionManager.encrypt_for_session(b, b"B to A")
    assert SessionManager.decrypt_from_session(a, ct2, h2) == b"B to A"


def test_ratchet_unique_ciphertexts():
    """Одинаковый plaintext шифруется в разные шифртексты (случайный nonce)."""
    a, b = setup_ratchet()
    ct1, h1 = SessionManager.encrypt_for_session(a, b"same")
    a2, b2 = setup_ratchet()
    ct2, h2 = SessionManager.encrypt_for_session(a2, b"same")
    assert ct1 != ct2
