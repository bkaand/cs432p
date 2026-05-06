"""
crypto_utils.py
---------------
Shared cryptographic helpers and wire-framing protocol for the CS432 project.

All hashing operations use SHA3-512.
All AES operations use AES-256 in CBC mode with PKCS#7 padding.
RSA-3072 keys are loaded from PEM files.
- RSA encryption / decryption uses OAEP with SHA3-512 (MGF1 SHA3-512).
- RSA signing / verification uses PKCS#1 v1.5 with SHA3-512.

The wire protocol is a simple length-prefixed JSON framing:
    [4 bytes big-endian unsigned length] [JSON-encoded UTF-8 payload]

Binary fields inside JSON are sent in hexadecimal.
"""

import json
import socket
import struct

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA3_512, HMAC as PyHMAC
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import pad, unpad


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

CHANNELS = ("IF100", "MATH101", "SPS101")

AES_BLOCK_SIZE = 16          # AES block size, also IV length
AES_KEY_LEN = 32             # AES-256
HMAC_KEY_LEN = 32            # 256-bit HMAC key
NONCE_LEN = 16               # 128-bit challenge

# Status strings used in authentication responses (must match exactly on both sides)
AUTH_OK_TEXT = b"Authentication Successful"
AUTH_FAIL_TEXT = b"Authentication Unsuccessful"
AUTH_CHANNEL_UNAVAILABLE = b"Channel Unavailable"


# -----------------------------------------------------------------------------
# Hashing helpers
# -----------------------------------------------------------------------------

def sha3_512(data: bytes) -> bytes:
    """Return the 64-byte SHA3-512 digest of `data`."""
    h = SHA3_512.new()
    h.update(data)
    return h.digest()


def reverse_str(s: str) -> str:
    """Return the input string with its characters reversed."""
    return s[::-1]


def password_hashes(password: str):
    """
    Compute the two password-derived hashes used in this project.
    Returns (h_pw, h_rev_pw) as 64-byte values.
    """
    h_pw = sha3_512(password.encode("utf-8"))
    h_rev_pw = sha3_512(reverse_str(password).encode("utf-8"))
    return h_pw, h_rev_pw


def derive_aes_key_iv_from_hash(h: bytes):
    """
    Given a 64-byte hash, derive an AES-256 key and a 128-bit IV.
        key = h[0:32]   (lower 32 bytes)
        iv  = h[32:48]  (next 16 bytes; the "lower half of the upper half")
    The remaining 16 bytes are discarded.
    """
    if len(h) != 64:
        raise ValueError("Expected a 64-byte hash for key/IV derivation")
    return h[0:AES_KEY_LEN], h[AES_KEY_LEN:AES_KEY_LEN + AES_BLOCK_SIZE]


def derive_hmac_key_from_hash(h: bytes) -> bytes:
    """Given a 64-byte hash, take its lower 32 bytes as an HMAC-SHA3-512 key."""
    if len(h) != 64:
        raise ValueError("Expected a 64-byte hash for HMAC key derivation")
    return h[0:HMAC_KEY_LEN]


# -----------------------------------------------------------------------------
# AES helpers
# -----------------------------------------------------------------------------

def aes_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """Encrypt `plaintext` using AES-256-CBC with PKCS#7 padding."""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(plaintext, AES_BLOCK_SIZE))


def aes_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt `ciphertext` using AES-256-CBC with PKCS#7 padding.
    Raises ValueError if padding is invalid (e.g. wrong key/IV).
    """
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES_BLOCK_SIZE)


# -----------------------------------------------------------------------------
# HMAC helpers (HMAC-SHA3-512)
# -----------------------------------------------------------------------------

def hmac_sha3_512(key: bytes, data: bytes) -> bytes:
    """Compute HMAC-SHA3-512 of `data` under `key`."""
    h = PyHMAC.new(key, digestmod=SHA3_512)
    h.update(data)
    return h.digest()


def hmac_verify(key: bytes, data: bytes, mac: bytes) -> bool:
    """Constant-time verification of HMAC-SHA3-512."""
    try:
        h = PyHMAC.new(key, digestmod=SHA3_512)
        h.update(data)
        h.verify(mac)
        return True
    except (ValueError, TypeError):
        return False


# -----------------------------------------------------------------------------
# RSA helpers
# -----------------------------------------------------------------------------

def load_rsa_key_from_file(path: str):
    """Load an RSA key (public or private) from a PEM file and return the key object."""
    with open(path, "rb") as f:
        return RSA.import_key(f.read())


def rsa_encrypt(pub_key, plaintext: bytes) -> bytes:
    """RSA-OAEP encrypt with SHA3-512 (and SHA3-512 MGF1)."""
    cipher = PKCS1_OAEP.new(pub_key, hashAlgo=SHA3_512)
    return cipher.encrypt(plaintext)


def rsa_decrypt(prv_key, ciphertext: bytes) -> bytes:
    """RSA-OAEP decrypt with SHA3-512."""
    cipher = PKCS1_OAEP.new(prv_key, hashAlgo=SHA3_512)
    return cipher.decrypt(ciphertext)


def rsa_sign(prv_key, data: bytes) -> bytes:
    """RSA-PKCS#1-v1.5 sign over SHA3-512 of `data`."""
    h = SHA3_512.new(data)
    return pkcs1_15.new(prv_key).sign(h)


def rsa_verify(pub_key, data: bytes, signature: bytes) -> bool:
    """Verify an RSA-PKCS#1-v1.5 signature over SHA3-512 of `data`."""
    try:
        h = SHA3_512.new(data)
        pkcs1_15.new(pub_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False


# -----------------------------------------------------------------------------
# Random helpers
# -----------------------------------------------------------------------------

def csprng_bytes(n: int) -> bytes:
    """Cryptographically-secure random bytes."""
    return get_random_bytes(n)


# -----------------------------------------------------------------------------
# Wire protocol: length-prefixed JSON framing
# -----------------------------------------------------------------------------

def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """Receive exactly `n` bytes from socket or raise ConnectionError on EOF."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("socket closed before all bytes received")
        buf.extend(chunk)
    return bytes(buf)


def send_msg(sock: socket.socket, obj: dict) -> None:
    """Send a Python dict as a length-prefixed UTF-8 JSON frame."""
    raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    sock.sendall(struct.pack(">I", len(raw)) + raw)


def recv_msg(sock: socket.socket) -> dict:
    """Receive a single length-prefixed UTF-8 JSON frame and return as dict."""
    length_prefix = _recv_exact(sock, 4)
    (length,) = struct.unpack(">I", length_prefix)
    if length == 0 or length > 16 * 1024 * 1024:  # 16 MB sanity cap
        raise ValueError(f"unreasonable frame length: {length}")
    raw = _recv_exact(sock, length)
    return json.loads(raw.decode("utf-8"))


# -----------------------------------------------------------------------------
# Hex helpers (for both wire transport and GUI display)
# -----------------------------------------------------------------------------

def to_hex(b: bytes) -> str:
    """Return uppercase hex string of `b`. Used everywhere on the GUIs."""
    return b.hex().upper()


def from_hex(h: str) -> bytes:
    """Inverse of `to_hex`."""
    return bytes.fromhex(h)


def short_hex(b: bytes, head: int = 16, tail: int = 8) -> str:
    """
    Truncated hex display for very long values (e.g. RSA moduli or signatures).
    Useful in compact log lines: keep the first `head` and last `tail` bytes.
    Full values should still be shown in dedicated text widgets.
    """
    h = to_hex(b)
    if len(b) <= head + tail:
        return h
    return f"{h[: head * 2]}...{h[-tail * 2:]} ({len(b)} bytes)"


# -----------------------------------------------------------------------------
# Compact enrollment payload encoding
# -----------------------------------------------------------------------------
# RSA-3072 with OAEP-SHA3-512 caps plaintext at 254 bytes. Hex-encoded JSON
# blows past that, so we use a tight binary format:
#
#     [1 byte: len(username)] [username utf-8 bytes]
#     [64 bytes: h(password)]
#     [64 bytes: h(reversed password)]
#     [1 byte: len(channel)]  [channel utf-8 bytes]
#
# Maximum size with a 32-byte username and 7-byte channel: 169 bytes.

def encode_enrollment(username: str, h_pw: bytes, h_rev_pw: bytes, channel: str) -> bytes:
    """Pack an enrollment payload into the compact binary format."""
    if len(h_pw) != 64 or len(h_rev_pw) != 64:
        raise ValueError("Password hashes must be 64 bytes (SHA3-512)")
    u = username.encode("utf-8")
    c = channel.encode("utf-8")
    if not (1 <= len(u) <= 32):
        raise ValueError("Username must be 1-32 UTF-8 bytes")
    if not (1 <= len(c) <= 16):
        raise ValueError("Channel name must be 1-16 UTF-8 bytes")
    return bytes([len(u)]) + u + h_pw + h_rev_pw + bytes([len(c)]) + c


def decode_enrollment(payload: bytes):
    """Inverse of `encode_enrollment`. Returns (username, h_pw, h_rev_pw, channel)."""
    if len(payload) < 1 + 1 + 64 + 64 + 1 + 1:
        raise ValueError("Enrollment payload too short")
    i = 0
    ulen = payload[i]; i += 1
    if ulen < 1 or ulen > 32 or i + ulen > len(payload):
        raise ValueError("Bad username length")
    username = payload[i:i + ulen].decode("utf-8"); i += ulen
    if i + 64 + 64 + 1 > len(payload):
        raise ValueError("Enrollment payload truncated before hashes")
    h_pw = payload[i:i + 64]; i += 64
    h_rev_pw = payload[i:i + 64]; i += 64
    clen = payload[i]; i += 1
    if clen < 1 or clen > 16 or i + clen != len(payload):
        raise ValueError("Bad channel length / trailing bytes")
    channel = payload[i:i + clen].decode("utf-8")
    return username, h_pw, h_rev_pw, channel