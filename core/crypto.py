"""Real RSA-2048 OAEP and AES-256-GCM cryptography handlers for the C2 transport.

This module implements a dual-layer crypto scheme:

1. Ephemeral RSA-2048 OAEP handshake to exchange a one-time session key.
2. Authenticated AES-256-GCM for all subsequent beacon heartbeats and task
   delivery, protecting confidentiality and integrity.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any


class CryptoError(Exception):
    """Raised for any cryptographic failure in the transport layer."""


@dataclass(frozen=True)
class AESCipher:
    """Authenticated AES-256-GCM encryption/decryption wrapper."""

    key: bytes
    iv_size: int = 12
    tag_size: int = 16

    def __post_init__(self) -> None:
        if len(self.key) != 32:
            raise CryptoError("AES-256 requires a 32-byte key")

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt plaintext, returning ``iv || ciphertext || tag``."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        if not plaintext:
            raise CryptoError("Cannot encrypt empty payload")
        iv = os.urandom(self.iv_size)
        aesgcm = AESGCM(self.key)
        ciphertext = aesgcm.encrypt(iv, plaintext, None)
        return iv + ciphertext

    def decrypt(self, blob: bytes) -> bytes:
        """Decrypt ``iv || ciphertext || tag`` back to the plaintext."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        if len(blob) < self.iv_size + self.tag_size:
            raise CryptoError("Ciphertext too short to contain IV and tag")
        iv, ciphertext = blob[: self.iv_size], blob[self.iv_size :]
        aesgcm = AESGCM(self.key)
        try:
            return aesgcm.decrypt(iv, ciphertext, None)
        except Exception as exc:  # pragma: no cover - timing guard
            raise CryptoError("AES-GCM authentication failed") from exc


@dataclass(frozen=True)
class RSACipher:
    """RSA-2048 OAEP public/private keypair handling."""

    private_key_pem: bytes
    public_key_pem: bytes

    @classmethod
    def generate(cls) -> RSACipher:
        """Generate a new 2048-bit RSA keypair."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_bytes = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        public_bytes = private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return cls(private_key_pem=private_bytes, public_key_pem=public_bytes)

    @classmethod
    def from_public_bytes(cls, public_pem: bytes) -> tuple[Any, RSACipher]:
        """Load a public key from PEM, returning the public key object."""
        from cryptography.hazmat.primitives import serialization

        public_key = serialization.load_pem_public_key(public_pem)
        return public_key, cls(private_key_pem=b"", public_key_pem=public_pem)

    def encrypt_with_public(self, payload: bytes) -> bytes:
        """Encrypt a payload with OAEP padding using only the public key."""
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding, rsa

        public_key = serialization.load_pem_public_key(self.public_key_pem)
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise CryptoError("public key is not an RSA key")
        max_plain = (public_key.key_size // 8) - 2 * hashes.SHA256().digest_size - 2
        if len(payload) > max_plain:
            raise CryptoError(
                f"RSA-OAEP plaintext exceeds {max_plain} bytes; use hybrid encryption"
            )
        encrypted = public_key.encrypt(
            payload,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return encrypted

    def decrypt_with_private(self, blob: bytes) -> bytes:
        """Decrypt an OAEP blob with the private key."""
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding, rsa

        private_key = serialization.load_pem_private_key(self.private_key_pem, None)
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise CryptoError("private key is not an RSA key")
        try:
            return private_key.decrypt(
                blob,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        except Exception as exc:  # pragma: no cover - guard
            raise CryptoError("RSA-OAEP decryption failed") from exc


class CryptoHandler:
    """High-level transport crypto: session key exchange + GCM packet wrapper.

    Provides a hybrid scheme where an ephemeral AES-256-GCM session key is
    generated per heartbeat and wrapped with the C2's RSA-2048 public key.
    """

    def __init__(self, rsa_cipher: RSACipher) -> None:
        self.rsa = rsa_cipher

    def create_session(self) -> dict[str, bytes | AESCipher]:
        """Generate a new AES-256 session key and its RSA-wrapped envelope."""
        key_bytes = os.urandom(32)
        aes = AESCipher(key=key_bytes)
        wrapped_key = self.rsa.encrypt_with_public(key_bytes)
        return {
            "session_key": key_bytes,
            "wrapped_key": wrapped_key,
            "aes_cipher": aes,
        }

    def unwrap_session(self, wrapped_key: bytes) -> AESCipher:
        """Decrypt a wrapped session key and return a ready AESCipher."""
        key_bytes = self.rsa.decrypt_with_private(wrapped_key)
        return AESCipher(key=key_bytes)

    def seal(self, aes: AESCipher, plaintext: bytes) -> bytes:
        """Seal plaintext with the session cipher."""
        return aes.encrypt(plaintext)

    def open(self, aes: AESCipher, blob: bytes) -> bytes:
        """Open an authenticated ciphertext with the session cipher."""
        return aes.decrypt(blob)
