"""
SessionManager – протоколы X3DH и Double Ratchet.

Исправления:
- Случайный nonce в каждом сообщении AES-256-GCM (формат: nonce||ciphertext)
- Верификация подписи SPK при initiate_session (защита от MITM)
- Корректный Double Ratchet: раздельные KDF_RK шаги для recv и send цепочек
- Защита от replay-атак (отслеживание (dh_pub_epoch, msg_num))
"""
import os
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
        self.root_key: bytes = None
        self.our_dh_priv: bytes = None
        self.our_dh_pub: bytes = None
        self.their_dh_pub: bytes = None
        self.send_chain_key: bytes = None
        self.recv_chain_key: bytes = None
        self.send_msg_num: int = 0
        self.recv_msg_num: int = 0
        self.prev_send_msg_num: int = 0
        # Для защиты от replay: хранит (bytes(their_dh_pub), msg_num)
        self._seen_msgs: set = None

    def _get_seen(self) -> set:
        if self._seen_msgs is None:
            self._seen_msgs = set()
        return self._seen_msgs


# ── Примитивы ────────────────────────────────────────────────────────────────

def _dh(priv: bytes, pub: bytes) -> bytes:
    return nacl.bindings.crypto_scalarmult(priv, pub)


def _hkdf(salt: bytes, ikm: bytes, info: bytes = b"", length: int = 32) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info)
    return hkdf.derive(ikm)


def _kdf_rk(root_key: bytes, dh_output: bytes):
    """KDF_RK из спецификации Double Ratchet. Возвращает (new_root_key, chain_key)."""
    out = _hkdf(salt=root_key, ikm=dh_output, info=b"WhisperRatchet", length=64)
    return out[:32], out[32:]


def _kdf_ck(chain_key: bytes):
    """KDF_CK: возвращает (new_chain_key, message_key) из текущего chain_key."""
    mk  = _hkdf(salt=b'\x01' * 32, ikm=chain_key, info=b"WhisperMessageKeys", length=32)
    ck  = _hkdf(salt=b'\x02' * 32, ikm=chain_key, info=b"WhisperChainKey",    length=32)
    return ck, mk


def _encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """AES-256-GCM с случайным nonce. Возвращает nonce(12) || ciphertext+tag."""
    nonce = os.urandom(config.IV_SIZE)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def _decrypt(key: bytes, data: bytes, aad: bytes = b"") -> bytes:
    """AES-256-GCM расшифрование. Ожидает формат nonce(12) || ciphertext+tag."""
    if len(data) < config.IV_SIZE:
        raise ValueError("Шифртекст слишком короткий")
    nonce, ct = data[:config.IV_SIZE], data[config.IV_SIZE:]
    return AESGCM(key).decrypt(nonce, ct, aad)


# ── Протокол X3DH + Double Ratchet ──────────────────────────────────────────

class SessionManager:

    @staticmethod
    def initiate_session(our_ik_priv: bytes, our_ik_pub: bytes, bundle: dict, opk_used=None):
        """
        Инициирует X3DH-сессию (сторона Alice).

        Выполняет:
        1. Верификацию подписи SPK Bob'а (защита от MITM).
        2. Четыре DH-операции X3DH.
        3. Начальный KDF_RK-шаг для инициализации send_chain_key.

        Возвращает: (state, ek_pub, dh4_bytes)
        """
        # ── 1. Верификация подписи SPK ────────────────────────────────────
        ik_b_ed25519_raw = base64.b64decode(bundle["ik_ed25519"])
        spk_pub          = base64.b64decode(bundle["spk"])
        spk_signature    = base64.b64decode(bundle["spk_signature"])
        spk_timestamp    = bundle["spk_timestamp"]
        try:
            verify_key = nacl.signing.VerifyKey(ik_b_ed25519_raw)
            verify_key.verify(spk_pub + spk_timestamp.encode(), spk_signature)
        except Exception as exc:
            raise ValueError(f"Неверная подпись SPK — возможна MITM-атака: {exc}")

        # ── 2. X3DH ──────────────────────────────────────────────────────
        ek_seed = os.urandom(32)
        ek_priv = nacl.bindings.crypto_box_seed_keypair(ek_seed)[0]
        ek_pub  = nacl.bindings.crypto_scalarmult_base(ek_priv)

        ik_b_pub = base64.b64decode(bundle["ik_x25519"])

        dh1 = _dh(our_ik_priv, spk_pub)   # IK_A × SPK_B
        dh2 = _dh(ek_priv,     ik_b_pub)  # EK_A × IK_B
        dh3 = _dh(ek_priv,     spk_pub)   # EK_A × SPK_B
        dh4 = b""
        if bundle.get("opk") and bundle["opk"].get("public"):
            opk_pub = base64.b64decode(bundle["opk"]["public"])
            dh4 = _dh(ek_priv, opk_pub)   # EK_A × OPK_B

        shared_secret = dh1 + dh2 + dh3 + dh4
        root_key = _hkdf(salt=bytes(32), ikm=shared_secret, info=b"root-key")

        # ── 3. Первый KDF_RK-шаг: инициализируем send_chain_key ──────────
        # DH(ek_priv, spk_pub) == DH(spk_priv, ek_pub) — симметрия Диффи-Хеллмана
        root_key, send_chain_key = _kdf_rk(root_key, _dh(ek_priv, spk_pub))

        state = RatchetState()
        state.root_key      = root_key
        state.our_dh_priv   = ek_priv
        state.our_dh_pub    = ek_pub
        state.their_dh_pub  = spk_pub
        state.send_chain_key = send_chain_key
        state.recv_chain_key = None  # будет инициализирован после первого ответа Bob'а

        return state, ek_pub, dh4

    @staticmethod
    def receive_session(our_ik_priv: bytes, our_ik_pub: bytes,
                        our_spk_priv: bytes, our_spk_pub: bytes,
                        opk_priv_dict: dict,
                        initiator_ik_pub: bytes, initiator_ek_pub: bytes,
                        used_opk_id=None):
        """
        Принимает X3DH-сессию (сторона Bob).

        Цепочки send/recv будут инициализированы при первом входящем сообщении
        (DH-шаговое обновление в decrypt_from_session).
        """
        dh1 = _dh(our_spk_priv,  initiator_ik_pub)   # SPK_B × IK_A
        dh2 = _dh(our_ik_priv,   initiator_ek_pub)    # IK_B  × EK_A
        dh3 = _dh(our_spk_priv,  initiator_ek_pub)    # SPK_B × EK_A
        dh4 = b""
        if used_opk_id is not None and used_opk_id in opk_priv_dict:
            dh4 = _dh(opk_priv_dict[used_opk_id], initiator_ek_pub)

        shared_secret = dh1 + dh2 + dh3 + dh4
        root_key = _hkdf(salt=bytes(32), ikm=shared_secret, info=b"root-key")

        state = RatchetState()
        state.root_key      = root_key
        state.our_dh_priv   = our_spk_priv
        state.our_dh_pub    = our_spk_pub
        state.their_dh_pub  = None   # None → DH-шаг сработает на первом recv
        state.send_chain_key = None
        state.recv_chain_key = None

        return state

    @staticmethod
    def encrypt_for_session(state: RatchetState, plaintext: bytes):
        """
        Шифрует одно сообщение, продвигая send_chain_key (KDF_CK).
        Возвращает (ciphertext_with_nonce, header).
        """
        if state.send_chain_key is None:
            raise ValueError("Цепочка отправки не инициализирована — дождитесь первого ответа")

        state.send_chain_key, mk = _kdf_ck(state.send_chain_key)
        aad = state.our_dh_pub + struct.pack(">I", state.send_msg_num)
        ciphertext = _encrypt(mk, plaintext, aad)

        header = {
            "dh_pub":       base64.b64encode(state.our_dh_pub).decode(),
            "msg_num":      state.send_msg_num,
            "prev_msg_num": state.prev_send_msg_num,
        }
        state.send_msg_num += 1
        return ciphertext, header

    @staticmethod
    def decrypt_from_session(state: RatchetState, ciphertext: bytes, header: dict) -> bytes:
        """
        Расшифровывает сообщение, выполняя DH-шаговое обновление при необходимости.

        DH-шаг Double Ratchet (при новом dh_pub от собеседника):
          1. KDF_RK(root, DH(our_priv, their_new_pub))  → новый recv_chain_key
          2. Генерация нашей новой DH-пары
          3. KDF_RK(root, DH(new_priv, their_new_pub))  → новый send_chain_key

        Это обеспечивает Forward Secrecy и Break-in Recovery.
        """
        their_dh_pub = base64.b64decode(header["dh_pub"])
        msg_num = header["msg_num"]

        # Replay-защита
        seen = state._get_seen()
        replay_key = (their_dh_pub, msg_num)
        if replay_key in seen:
            raise ValueError("Повторное сообщение отклонено (replay attack)")

        # ── DH-шаговое обновление ─────────────────────────────────────────
        if their_dh_pub != state.their_dh_pub:
            state.prev_send_msg_num = state.send_msg_num
            state.send_msg_num  = 0
            state.recv_msg_num  = 0
            # _seen_msgs не сбрасываем: (their_dh_pub, msg_num) содержит DH-эпоху,
            # поэтому старые записи не конфликтуют с новыми.

            # Шаг A: recv chain
            dh_recv = _dh(state.our_dh_priv, their_dh_pub)
            state.root_key, state.recv_chain_key = _kdf_rk(state.root_key, dh_recv)
            state.their_dh_pub = their_dh_pub

            # Шаг B: новая DH-пара + send chain
            new_priv = nacl.bindings.crypto_box_seed_keypair(os.urandom(32))[0]
            new_pub  = nacl.bindings.crypto_scalarmult_base(new_priv)
            dh_send  = _dh(new_priv, their_dh_pub)
            state.root_key, state.send_chain_key = _kdf_rk(state.root_key, dh_send)
            state.our_dh_priv = new_priv
            state.our_dh_pub  = new_pub

        if state.recv_chain_key is None:
            raise ValueError("recv_chain_key не инициализирован")

        # Пропускаем сообщения, пришедшие не по порядку
        while state.recv_msg_num < msg_num:
            state.recv_chain_key, _ = _kdf_ck(state.recv_chain_key)
            state.recv_msg_num += 1

        state.recv_chain_key, mk = _kdf_ck(state.recv_chain_key)
        aad = their_dh_pub + struct.pack(">I", msg_num)
        plaintext = _decrypt(mk, ciphertext, aad)

        state.recv_msg_num += 1
        # Добавляем в seen ЧЕРЕЗ state, чтобы не потерять ссылку при ratchet-сбросе
        state._get_seen().add(replay_key)
        return plaintext
