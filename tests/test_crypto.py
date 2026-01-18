"""Unit tests for the real cryptographic primitives."""

import os

import pytest

from core.crypto import AESCipher, CryptoError, CryptoHandler, RSACipher


class TestRSACipher:
    def test_generate_keypair_roundtrip(self):
        rsa = RSACipher.generate()
        assert len(rsa.private_key_pem) > 0
        assert len(rsa.public_key_pem) > 0
        payload = b"AEF session key material"
        encrypted = rsa.encrypt_with_public(payload)
        decrypted = rsa.decrypt_with_private(encrypted)
        assert decrypted == payload

    def test_decrypt_with_wrong_key_fails(self):
        rsa1 = RSACipher.generate()
        rsa2 = RSACipher.generate()
        encrypted = rsa1.encrypt_with_public(b"secret")
        with pytest.raises(CryptoError, match="OAEP decryption failed"):
            rsa2.decrypt_with_private(encrypted)

    def test_encrypt_oversized_fails(self):
        rsa = RSACipher.generate()
        with pytest.raises(CryptoError, match="exceeds"):
            rsa.encrypt_with_public(b"A" * 512)


class TestAESCipher:
    def test_roundtrip(self):
        key = os.urandom(32)
        aes = AESCipher(key=key)
        plaintext = b"beacon heartbeat payload"
        blob = aes.encrypt(plaintext)
        assert blob != plaintext
        decrypted = aes.decrypt(blob)
        assert decrypted == plaintext

    def test_wrong_key_fails(self):
        aes1 = AESCipher(key=b"\x01" * 32)
        aes2 = AESCipher(key=b"\x02" * 32)
        blob = aes1.encrypt(b"secret")
        with pytest.raises(CryptoError):
            aes2.decrypt(blob)

    def test_invalid_key_size(self):
        with pytest.raises(CryptoError, match="32-byte"):
            AESCipher(key=b"\x01" * 16)


class TestCryptoHandler:
    def test_session_seal_open(self, rsa_cipher):
        from core.crypto import AESCipher

        handler = CryptoHandler(rsa_cipher)
        session = handler.create_session()
        aes = session["aes_cipher"]
        assert isinstance(aes, AESCipher)
        plaintext = b"hello from the agent"
        sealed = handler.seal(aes, plaintext)
        opened = handler.open(aes, sealed)
        assert opened == plaintext
