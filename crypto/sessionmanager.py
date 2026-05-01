import os
import hashlib
import struct
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import nacl.bindings
import nacl.signing
import config

class RatchetState:
    def __init__(self):
        self.root_key = None
        self.our_dh_priv = None
        self.our_dh_pub = None
        self.their_dh_pub = None
        self.send_chain_key = None
        self.recv_chain_key = None
        self.send_msg_num = 0
        self.recv_msg_num = 0
        self.prev_send_msg_num = 0

def _dh(priv, pub):
    return nacl.bindings.crypto_scalarmult(priv, pub)

def _hkdf(salt, ikm, info=b"", length=32):
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info)
    return hkdf.derive(ikm)

def _encrypt(key, plaintext, aad=b""):
    aes = AESGCM(key)
    return aes.encrypt(b'\x00' * 12, plaintext, aad)

def _decrypt(key, ciphertext, aad=b""):
    aes = AESGCM(key)
    return aes.decrypt(b'\x00' * 12, ciphertext, aad)

class SessionManager:
    @staticmethod
    def initiate_session(our_ik_priv, our_ik_pub, bundle, opk_used=None):
        ek_priv = nacl.bindings.crypto_box_seed_keypair(os.urandom(32))[0]
        ek_pub = nacl.bindings.crypto_scalarmult_base(ek_priv)
        
        spk_pub = base64.b64decode(bundle["spk"])
        ik_b_pub = base64.b64decode(bundle["ik_x25519"])
        
        dh1 = _dh(our_ik_priv, spk_pub)
        dh2 = _dh(ek_priv, ik_b_pub)
        dh3 = _dh(ek_priv, spk_pub)
        dh4 = b""
        
        shared_secret = dh1 + dh2 + dh3 + dh4
        root_key = _hkdf(salt=bytes(32), ikm=shared_secret, info=b"root-key")
        
        state = RatchetState()
        state.root_key = root_key
        state.our_dh_priv = ek_priv
        state.our_dh_pub = ek_pub
        state.their_dh_pub = spk_pub
        
        # ОБЕ цепочки инициализируются одинаково из root_key
        chain_key = _hkdf(root_key, b"", info=b"chain")
        state.send_chain_key = chain_key
        state.recv_chain_key = chain_key
        
        return state, ek_pub, dh4

    @staticmethod
    def receive_session(our_ik_priv, our_ik_pub, our_spk_priv, our_spk_pub,
                        opk_priv_dict, initiator_ik_pub, initiator_ek_pub, used_opk_id=None):
        dh1 = _dh(our_spk_priv, initiator_ik_pub)
        dh2 = _dh(our_ik_priv, initiator_ek_pub)
        dh3 = _dh(our_spk_priv, initiator_ek_pub)
        dh4 = b""
        
        shared_secret = dh1 + dh2 + dh3 + dh4
        root_key = _hkdf(salt=bytes(32), ikm=shared_secret, info=b"root-key")
        
        state = RatchetState()
        state.root_key = root_key
        state.our_dh_priv = our_spk_priv
        state.our_dh_pub = our_spk_pub
        state.their_dh_pub = initiator_ek_pub
        
        # ОБЕ цепочки инициализируются одинаково из root_key
        chain_key = _hkdf(root_key, b"", info=b"chain")
        state.send_chain_key = chain_key
        state.recv_chain_key = chain_key
        
        return state

    @staticmethod
    def encrypt_for_session(state: RatchetState, plaintext: bytes):
        mk = _hkdf(state.send_chain_key, b"", info=b"message-key")
        aad = state.our_dh_pub + struct.pack(">I", state.send_msg_num)
        ciphertext = _encrypt(mk, plaintext, aad)
        header = {
            "dh_pub": base64.b64encode(state.our_dh_pub).decode(),
            "msg_num": state.send_msg_num,
            "prev_msg_num": state.prev_send_msg_num
        }
        state.send_chain_key = _hkdf(state.send_chain_key, b"", info=b"chain-advance")
        state.send_msg_num += 1
        return ciphertext, header

    @staticmethod
    def decrypt_from_session(state: RatchetState, ciphertext: bytes, header: dict) -> bytes:
        their_dh_pub = base64.b64decode(header["dh_pub"])
        msg_num = header["msg_num"]
        
        if their_dh_pub != state.their_dh_pub:
            dh_output = _dh(state.our_dh_priv, their_dh_pub)
            state.root_key = _hkdf(state.root_key, dh_output, info=b"root-update")
            chain_key = _hkdf(state.root_key, b"", info=b"chain")
            state.recv_chain_key = chain_key
            state.send_chain_key = chain_key
            state.recv_msg_num = 0
            
            new_priv = nacl.bindings.crypto_box_seed_keypair(os.urandom(32))[0]
            new_pub = nacl.bindings.crypto_scalarmult_base(new_priv)
            state.our_dh_priv = new_priv
            state.our_dh_pub = new_pub
            state.send_msg_num = 0
            state.their_dh_pub = their_dh_pub
        
        while state.recv_msg_num < msg_num:
            state.recv_chain_key = _hkdf(state.recv_chain_key, b"", info=b"chain-advance")
            state.recv_msg_num += 1
        
        mk = _hkdf(state.recv_chain_key, b"", info=b"message-key")
        aad = their_dh_pub + struct.pack(">I", msg_num)
        plaintext = _decrypt(mk, ciphertext, aad)
        state.recv_chain_key = _hkdf(state.recv_chain_key, b"", info=b"chain-advance")
        state.recv_msg_num += 1
        return plaintext