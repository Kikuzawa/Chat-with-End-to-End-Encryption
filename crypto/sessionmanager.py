"""
SessionManager – протоколы X3DH и Double Ratchet.
"""
import os
import sys
import struct
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import nacl.bindings
import nacl.signing
import config

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from log_utils import get_file_logger, h, SEP, SEP2

_log = get_file_logger("crypto", "crypto.log")


def _L(msg: str):
    _log.info(msg)


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
        """Инициирует X3DH-сессию (сторона Alice/отправитель)."""
        _L(SEP2)
        _L("[CRYPTO/X3DH/INITIATE] ▶ СТАРТ  X3DH инициация сессии (сторона отправителя)")
        _L(f"[CRYPTO/X3DH/INITIATE]   IK_A_pub  = {h(our_ik_pub)}")

        # ── 1. Верификация подписи SPK ────────────────────────────────────
        _L(SEP)
        _L("[CRYPTO/X3DH/INITIATE] [ШАГ 1] Верификация подписи SPK получателя (защита от MITM)")
        ik_b_ed25519_raw = base64.b64decode(bundle["ik_ed25519"])
        spk_pub          = base64.b64decode(bundle["spk"])
        spk_signature    = base64.b64decode(bundle["spk_signature"])
        spk_timestamp    = bundle["spk_timestamp"]
        _L(f"[CRYPTO/X3DH/INITIATE]   IK_B_ed25519 = {h(ik_b_ed25519_raw)}")
        _L(f"[CRYPTO/X3DH/INITIATE]   SPK_B_pub    = {h(spk_pub)}")
        _L(f"[CRYPTO/X3DH/INITIATE]   SPK подписан: {spk_timestamp}")
        try:
            verify_key = nacl.signing.VerifyKey(ik_b_ed25519_raw)
            verify_key.verify(spk_pub + spk_timestamp.encode(), spk_signature)
            _L("[CRYPTO/X3DH/INITIATE]   ✓ РЕЗУЛЬТАТ: Подпись SPK верна — MITM не обнаружен")
        except Exception as exc:
            _L(f"[CRYPTO/X3DH/INITIATE]   ✗ ОШИБКА: Подпись SPK неверна! {exc}")
            raise ValueError(f"Неверная подпись SPK — возможна MITM-атака: {exc}")

        # ── 2. X3DH ──────────────────────────────────────────────────────
        _L(SEP)
        _L("[CRYPTO/X3DH/INITIATE] [ШАГ 2] Генерация эфемерного ключа EK_A")
        ek_seed = os.urandom(32)
        ek_priv = nacl.bindings.crypto_box_seed_keypair(ek_seed)[0]
        ek_pub  = nacl.bindings.crypto_scalarmult_base(ek_priv)
        _L(f"[CRYPTO/X3DH/INITIATE]   EK_A_pub = {h(ek_pub)}  (одноразовый эфемерный ключ)")

        ik_b_pub = base64.b64decode(bundle["ik_x25519"])
        _L(f"[CRYPTO/X3DH/INITIATE]   IK_B_pub = {h(ik_b_pub)}")

        _L(SEP)
        _L("[CRYPTO/X3DH/INITIATE] [ШАГ 3] Четыре DH-операции X3DH")
        _L("[CRYPTO/X3DH/INITIATE]   Формула: SS = DH1 ‖ DH2 ‖ DH3 ‖ DH4")

        dh1 = _dh(our_ik_priv, spk_pub)
        _L(f"[CRYPTO/X3DH/INITIATE]   DH1 = DH(IK_A × SPK_B)  = {h(dh1)}")

        dh2 = _dh(ek_priv, ik_b_pub)
        _L(f"[CRYPTO/X3DH/INITIATE]   DH2 = DH(EK_A × IK_B)   = {h(dh2)}")

        dh3 = _dh(ek_priv, spk_pub)
        _L(f"[CRYPTO/X3DH/INITIATE]   DH3 = DH(EK_A × SPK_B)  = {h(dh3)}")

        dh4 = b""
        if bundle.get("opk") and bundle["opk"].get("public"):
            opk_pub = base64.b64decode(bundle["opk"]["public"])
            dh4 = _dh(ek_priv, opk_pub)
            _L(f"[CRYPTO/X3DH/INITIATE]   DH4 = DH(EK_A × OPK_B)  = {h(dh4)}  (OPK использован)")
        else:
            _L("[CRYPTO/X3DH/INITIATE]   DH4 = b''  (OPK не предоставлен)")

        shared_secret = dh1 + dh2 + dh3 + dh4
        _L(SEP)
        _L(f"[CRYPTO/X3DH/INITIATE] [ШАГ 4] Вычисление Shared Secret")
        _L(f"[CRYPTO/X3DH/INITIATE]   SS = DH1 ‖ DH2 ‖ DH3 ‖ DH4  ({len(shared_secret)} байт)")
        _L(f"[CRYPTO/X3DH/INITIATE]   SS[0:12]  = {h(shared_secret)}")
        _L(f"[CRYPTO/X3DH/INITIATE]   SS[32:44] = {h(shared_secret[32:])}")
        _L(f"[CRYPTO/X3DH/INITIATE]   SS[64:76] = {h(shared_secret[64:])}")

        root_key = _hkdf(salt=bytes(32), ikm=shared_secret, info=b"root-key")
        _L(SEP)
        _L("[CRYPTO/X3DH/INITIATE] [ШАГ 5] Вывод Root Key через HKDF-SHA256")
        _L(f"[CRYPTO/X3DH/INITIATE]   HKDF(salt=0x00*32, ikm=SS, info='root-key')")
        _L(f"[CRYPTO/X3DH/INITIATE]   root_key = {h(root_key)}  (32 байта)")

        # ── 3. Первый KDF_RK-шаг ─────────────────────────────────────────
        _L(SEP)
        _L("[CRYPTO/X3DH/INITIATE] [ШАГ 6] Первый KDF_RK шаг — инициализация send_chain_key")
        _L("[CRYPTO/X3DH/INITIATE]   dh_init = DH(EK_A × SPK_B)  (совпадает с DH3)")
        dh_init = _dh(ek_priv, spk_pub)
        root_key, send_chain_key = _kdf_rk(root_key, dh_init)
        _L(f"[CRYPTO/X3DH/INITIATE]   KDF_RK(root_key, dh_init) →")
        _L(f"[CRYPTO/X3DH/INITIATE]   new_root_key     = {h(root_key)}")
        _L(f"[CRYPTO/X3DH/INITIATE]   send_chain_key   = {h(send_chain_key)}")

        state = RatchetState()
        state.root_key       = root_key
        state.our_dh_priv    = ek_priv
        state.our_dh_pub     = ek_pub
        state.their_dh_pub   = spk_pub
        state.send_chain_key = send_chain_key
        state.recv_chain_key = None

        _L(SEP)
        _L("[CRYPTO/X3DH/INITIATE] ✓ ГОТОВО  RatchetState создан (сторона отправителя)")
        _L(f"[CRYPTO/X3DH/INITIATE]   our_dh_pub  = {h(state.our_dh_pub)}  (EK_A)")
        _L(f"[CRYPTO/X3DH/INITIATE]   their_dh_pub = {h(state.their_dh_pub)}  (SPK_B)")
        _L(f"[CRYPTO/X3DH/INITIATE]   send_chain_key готов, recv_chain_key = None")
        _L(SEP2)

        return state, ek_pub, dh4

    @staticmethod
    def receive_session(our_ik_priv: bytes, our_ik_pub: bytes,
                        our_spk_priv: bytes, our_spk_pub: bytes,
                        opk_priv_dict: dict,
                        initiator_ik_pub: bytes, initiator_ek_pub: bytes,
                        used_opk_id=None):
        """Принимает X3DH-сессию (сторона Bob/получатель)."""
        _L(SEP2)
        _L("[CRYPTO/X3DH/RECEIVE] ▶ СТАРТ  X3DH приём сессии (сторона получателя)")
        _L(f"[CRYPTO/X3DH/RECEIVE]   IK_B_pub   = {h(our_ik_pub)}")
        _L(f"[CRYPTO/X3DH/RECEIVE]   SPK_B_pub  = {h(our_spk_pub)}")
        _L(f"[CRYPTO/X3DH/RECEIVE]   IK_A_pub   = {h(initiator_ik_pub)}  (от отправителя)")
        _L(f"[CRYPTO/X3DH/RECEIVE]   EK_A_pub   = {h(initiator_ek_pub)}  (эфемерный от отправителя)")
        _L(f"[CRYPTO/X3DH/RECEIVE]   OPK_ID     = {str(used_opk_id)[:24] if used_opk_id else 'нет'}")

        _L(SEP)
        _L("[CRYPTO/X3DH/RECEIVE] [ШАГ 1] Четыре симметричные DH-операции X3DH")
        _L("[CRYPTO/X3DH/RECEIVE]   Формула: SS = DH1 ‖ DH2 ‖ DH3 ‖ DH4")

        dh1 = _dh(our_spk_priv, initiator_ik_pub)
        _L(f"[CRYPTO/X3DH/RECEIVE]   DH1 = DH(SPK_B × IK_A)   = {h(dh1)}")

        dh2 = _dh(our_ik_priv, initiator_ek_pub)
        _L(f"[CRYPTO/X3DH/RECEIVE]   DH2 = DH(IK_B  × EK_A)   = {h(dh2)}")

        dh3 = _dh(our_spk_priv, initiator_ek_pub)
        _L(f"[CRYPTO/X3DH/RECEIVE]   DH3 = DH(SPK_B × EK_A)   = {h(dh3)}")

        dh4 = b""
        opk_found = used_opk_id is not None and used_opk_id in opk_priv_dict
        if opk_found:
            dh4 = _dh(opk_priv_dict[used_opk_id], initiator_ek_pub)
            _L(f"[CRYPTO/X3DH/RECEIVE]   DH4 = DH(OPK_B × EK_A)  = {h(dh4)}  (OPK найден)")
        else:
            _L(f"[CRYPTO/X3DH/RECEIVE]   DH4 = b''  (OPK не найден, id={used_opk_id is not None})")

        shared_secret = dh1 + dh2 + dh3 + dh4
        _L(SEP)
        _L(f"[CRYPTO/X3DH/RECEIVE] [ШАГ 2] Вычисление Shared Secret")
        _L(f"[CRYPTO/X3DH/RECEIVE]   SS = DH1 ‖ DH2 ‖ DH3 ‖ DH4  ({len(shared_secret)} байт)")
        _L(f"[CRYPTO/X3DH/RECEIVE]   SS[0:12]  = {h(shared_secret)}")
        _L(f"[CRYPTO/X3DH/RECEIVE]   SS[32:44] = {h(shared_secret[32:])}")

        root_key = _hkdf(salt=bytes(32), ikm=shared_secret, info=b"root-key")
        _L(SEP)
        _L("[CRYPTO/X3DH/RECEIVE] [ШАГ 3] Вывод Root Key через HKDF-SHA256")
        _L(f"[CRYPTO/X3DH/RECEIVE]   HKDF(salt=0x00*32, ikm=SS, info='root-key')")
        _L(f"[CRYPTO/X3DH/RECEIVE]   root_key = {h(root_key)}  (32 байта)")

        state = RatchetState()
        state.root_key       = root_key
        state.our_dh_priv    = our_spk_priv
        state.our_dh_pub     = our_spk_pub
        state.their_dh_pub   = None
        state.send_chain_key = None
        state.recv_chain_key = None

        _L(SEP)
        _L("[CRYPTO/X3DH/RECEIVE] ✓ ГОТОВО  RatchetState создан (сторона получателя)")
        _L(f"[CRYPTO/X3DH/RECEIVE]   our_dh_pub   = {h(state.our_dh_pub)}  (SPK_B)")
        _L("[CRYPTO/X3DH/RECEIVE]   their_dh_pub = None  (ждём первое сообщение)")
        _L("[CRYPTO/X3DH/RECEIVE]   send_chain_key = None, recv_chain_key = None")
        _L(SEP2)

        return state

    @staticmethod
    def encrypt_for_session(state: RatchetState, plaintext: bytes):
        """Шифрует одно сообщение, продвигая send_chain_key (KDF_CK)."""
        if state.send_chain_key is None:
            raise ValueError("Цепочка отправки не инициализирована — дождитесь первого ответа")

        _L(SEP)
        _L(f"[CRYPTO/RATCHET/ENC] ▶ ШИФРОВАНИЕ  msg_num={state.send_msg_num}  "
           f"plaintext={len(plaintext)} байт")
        _L(f"[CRYPTO/RATCHET/ENC]   our_dh_pub      = {h(state.our_dh_pub)}")
        _L(f"[CRYPTO/RATCHET/ENC]   send_chain_key  = {h(state.send_chain_key)}")

        _L("[CRYPTO/RATCHET/ENC] [KDF_CK] Продвижение цепочки отправки")
        _L("[CRYPTO/RATCHET/ENC]   KDF_CK(send_chain_key) → new_chain_key + message_key")
        state.send_chain_key, mk = _kdf_ck(state.send_chain_key)
        _L(f"[CRYPTO/RATCHET/ENC]   new_send_chain_key = {h(state.send_chain_key)}")
        _L(f"[CRYPTO/RATCHET/ENC]   message_key        = {h(mk)}  (32 байта, AES-256)")

        aad = state.our_dh_pub + struct.pack(">I", state.send_msg_num)
        _L(f"[CRYPTO/RATCHET/ENC]   AAD = our_dh_pub ‖ msg_num  ({len(aad)} байт)")

        _L("[CRYPTO/RATCHET/ENC] [AES-256-GCM] Шифрование открытого текста")
        nonce = os.urandom(config.IV_SIZE)
        ct_with_tag = AESGCM(mk).encrypt(nonce, plaintext, aad)
        ciphertext = nonce + ct_with_tag
        _L(f"[CRYPTO/RATCHET/ENC]   nonce      = {nonce.hex()}  (12 байт, случайный)")
        _L(f"[CRYPTO/RATCHET/ENC]   ciphertext = nonce ‖ ct ‖ tag  ({len(ciphertext)} байт)")
        _L(f"[CRYPTO/RATCHET/ENC]   ct_preview = {h(ciphertext[12:], 12)}")
        _L(f"[CRYPTO/RATCHET/ENC]   overhead   = 12 (nonce) + 16 (GCM tag) = 28 байт")

        header = {
            "dh_pub":       base64.b64encode(state.our_dh_pub).decode(),
            "msg_num":      state.send_msg_num,
            "prev_msg_num": state.prev_send_msg_num,
        }
        state.send_msg_num += 1
        _L(f"[CRYPTO/RATCHET/ENC] ✓ ГОТОВО  msg_num={state.send_msg_num - 1} зашифровано")
        _L(SEP)

        return ciphertext, header

    @staticmethod
    def decrypt_from_session(state: RatchetState, ciphertext: bytes, header: dict) -> bytes:
        """Расшифровывает сообщение с DH-шаговым обновлением при необходимости."""
        their_dh_pub = base64.b64decode(header["dh_pub"])
        msg_num = header["msg_num"]

        _L(SEP)
        _L(f"[CRYPTO/RATCHET/DEC] ▶ РАСШИФРОВКА  msg_num={msg_num}  "
           f"ciphertext={len(ciphertext)} байт")
        _L(f"[CRYPTO/RATCHET/DEC]   their_dh_pub (из header) = {h(their_dh_pub)}")
        _L(f"[CRYPTO/RATCHET/DEC]   our_dh_priv  (текущий)   = {h(state.our_dh_priv)}")

        # Replay-защита
        seen = state._get_seen()
        replay_key = (their_dh_pub, msg_num)
        if replay_key in seen:
            _L(f"[CRYPTO/RATCHET/DEC] ✗ ОШИБКА: Повторное сообщение (replay attack) msg_num={msg_num}")
            raise ValueError("Повторное сообщение отклонено (replay attack)")

        # ── DH-шаговое обновление ─────────────────────────────────────────
        dh_step_done = False
        if their_dh_pub != state.their_dh_pub:
            dh_step_done = True
            _L("[CRYPTO/RATCHET/DEC] [DH STEP] Новый DH ключ отправителя → выполняем DH шаг")
            _L(f"[CRYPTO/RATCHET/DEC] [DH STEP]   old their_dh_pub = "
               f"{'None' if state.their_dh_pub is None else h(state.their_dh_pub)}")
            _L(f"[CRYPTO/RATCHET/DEC] [DH STEP]   new their_dh_pub = {h(their_dh_pub)}")

            state.prev_send_msg_num = state.send_msg_num
            state.send_msg_num  = 0
            state.recv_msg_num  = 0

            _L("[CRYPTO/RATCHET/DEC] [DH STEP] ШАГ A: recv_chain_key")
            dh_recv = _dh(state.our_dh_priv, their_dh_pub)
            _L(f"[CRYPTO/RATCHET/DEC] [DH STEP]   dh_recv = DH(our_priv × their_pub) = {h(dh_recv)}")
            state.root_key, state.recv_chain_key = _kdf_rk(state.root_key, dh_recv)
            _L(f"[CRYPTO/RATCHET/DEC] [DH STEP]   KDF_RK → new_root_key    = {h(state.root_key)}")
            _L(f"[CRYPTO/RATCHET/DEC] [DH STEP]   KDF_RK → recv_chain_key  = {h(state.recv_chain_key)}")
            state.their_dh_pub = their_dh_pub

            _L("[CRYPTO/RATCHET/DEC] [DH STEP] ШАГ B: Новая DH пара + send_chain_key")
            new_priv = nacl.bindings.crypto_box_seed_keypair(os.urandom(32))[0]
            new_pub  = nacl.bindings.crypto_scalarmult_base(new_priv)
            dh_send  = _dh(new_priv, their_dh_pub)
            _L(f"[CRYPTO/RATCHET/DEC] [DH STEP]   new our_dh_pub = {h(new_pub)}")
            _L(f"[CRYPTO/RATCHET/DEC] [DH STEP]   dh_send = DH(new_priv × their_pub) = {h(dh_send)}")
            state.root_key, state.send_chain_key = _kdf_rk(state.root_key, dh_send)
            _L(f"[CRYPTO/RATCHET/DEC] [DH STEP]   KDF_RK → new_root_key    = {h(state.root_key)}")
            _L(f"[CRYPTO/RATCHET/DEC] [DH STEP]   KDF_RK → send_chain_key  = {h(state.send_chain_key)}")
            state.our_dh_priv = new_priv
            state.our_dh_pub  = new_pub
        else:
            _L("[CRYPTO/RATCHET/DEC]   DH ключ не изменился — DH шаг не нужен")

        if state.recv_chain_key is None:
            _L("[CRYPTO/RATCHET/DEC] ✗ ОШИБКА: recv_chain_key не инициализирован")
            raise ValueError("recv_chain_key не инициализирован")

        if state.recv_msg_num < msg_num:
            _L(f"[CRYPTO/RATCHET/DEC]   Пропуск {msg_num - state.recv_msg_num} "
               f"сообщений (recv_num={state.recv_msg_num} < msg_num={msg_num})")
        while state.recv_msg_num < msg_num:
            state.recv_chain_key, _ = _kdf_ck(state.recv_chain_key)
            state.recv_msg_num += 1

        _L(f"[CRYPTO/RATCHET/DEC]   recv_chain_key = {h(state.recv_chain_key)}")
        _L("[CRYPTO/RATCHET/DEC] [KDF_CK] Продвижение цепочки получения")
        state.recv_chain_key, mk = _kdf_ck(state.recv_chain_key)
        _L(f"[CRYPTO/RATCHET/DEC]   new_recv_chain_key = {h(state.recv_chain_key)}")
        _L(f"[CRYPTO/RATCHET/DEC]   message_key        = {h(mk)}  (32 байта, AES-256)")

        aad = their_dh_pub + struct.pack(">I", msg_num)
        _L(f"[CRYPTO/RATCHET/DEC]   AAD = their_dh_pub ‖ msg_num  ({len(aad)} байт)")

        _L("[CRYPTO/RATCHET/DEC] [AES-256-GCM] Расшифровка")
        nonce, ct = ciphertext[:config.IV_SIZE], ciphertext[config.IV_SIZE:]
        _L(f"[CRYPTO/RATCHET/DEC]   nonce      = {nonce.hex()}  (12 байт)")
        _L(f"[CRYPTO/RATCHET/DEC]   ct+tag     = {h(ct)}  ({len(ct)} байт)")

        try:
            plaintext = AESGCM(mk).decrypt(nonce, ct, aad)
            _L(f"[CRYPTO/RATCHET/DEC] ✓ ГОТОВО  plaintext = {len(plaintext)} байт")
            try:
                preview = plaintext[:40].decode('utf-8')
                _L(f"[CRYPTO/RATCHET/DEC]   текст = '{preview}{'...' if len(plaintext) > 40 else ''}'")
            except Exception:
                pass
        except Exception as e:
            _L(f"[CRYPTO/RATCHET/DEC] ✗ ОШИБКА AES-GCM: {e} — неверный ключ или тег аутентификации")
            raise

        state.recv_msg_num += 1
        state._get_seen().add(replay_key)
        _L(SEP)
        return plaintext
