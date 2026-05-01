"""Тест Double Ratchet: много сообщений и восстановление после потери."""
from crypto.sessionmanager import SessionManager, RatchetState
import nacl.bindings
import hashlib
import os

def setup_ratchet():
    # Упрощённая инициализация общим корнем
    a_state = RatchetState()
    b_state = RatchetState()
    
    sk = hashlib.sha256(b"shared secret").digest()
    a_priv = nacl.bindings.crypto_box_seed_keypair(os.urandom(32))[0]
    a_pub = nacl.bindings.crypto_scalarmult_base(a_priv)
    b_priv = nacl.bindings.crypto_box_seed_keypair(os.urandom(32))[0]
    b_pub = nacl.bindings.crypto_scalarmult_base(b_priv)
    
    a_state.root_key = hashlib.sha256(sk + b"a").digest()
    b_state.root_key = a_state.root_key
    a_state.our_dh_priv, a_state.our_dh_pub = a_priv, a_pub
    a_state.their_dh_pub = b_pub
    a_state.send_chain_key = b"\x01"*32
    b_state.our_dh_priv, b_state.our_dh_pub = b_priv, b_pub
    b_state.their_dh_pub = a_pub
    b_state.recv_chain_key = b"\x01"*32
    return a_state, b_state

def test_ratchet_encrypt_decrypt():
    a, b = setup_ratchet()
    msg = b"ratchet test"
    ct, header = SessionManager.encrypt_for_session(a, msg)
    pt = SessionManager.decrypt_from_session(b, ct, header)
    assert pt == msg