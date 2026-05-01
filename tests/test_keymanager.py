"""Тесты KeyManager (генерация ключей, сохранение)."""
import os, json, tempfile
from crypto.keymanager import KeyManager

def test_generate_keys():
    km = KeyManager(tempfile.mktemp(suffix=".json"))
    km.generate_identity_key()
    km.generate_spk()
    km.generate_opks(10)
    assert len(km.ik_x25519_priv) == 32
    assert len(km.spk_signature) == 64
    assert len(km.opks) == 10

def test_save_load():
    km = KeyManager("/tmp/test_keys.json")
    km.generate_identity_key()
    km.generate_spk()
    km.generate_opks(1)
    km.save_keys("alice")
    km2 = KeyManager.load_keys("/tmp/test_keys.json")
    assert km2.ik_x25519_pub == km.ik_x25519_pub
    assert km2.spk_pub == km.spk_pub