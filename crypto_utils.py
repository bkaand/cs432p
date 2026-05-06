"""
shared crypto helpers + wire protocol for the cs432 project.
sha3-512 everywhere, aes-256-cbc, rsa-3072 (oaep + pkcs1v15).
wire format: 4-byte big-endian length prefix + utf-8 json. binary fields as hex.
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


CHANNELS = ("IF100", "MATH101", "SPS101")

AES_BLOCK_SIZE = 16          # also iv length
AES_KEY_LEN = 32             # aes-256
HMAC_KEY_LEN = 32
NONCE_LEN = 16               # 128-bit challenge

# must match exactly on both sides
AUTH_OK_TEXT = b"Authentication Successful"
AUTH_FAIL_TEXT = b"Authentication Unsuccessful"
AUTH_CHANNEL_UNAVAILABLE = b"Channel Unavailable"


def sha3_512(data: bytes) -> bytes:
    h = SHA3_512.new()
    h.update(data)
    return h.digest()


def reverse_str(s: str) -> str:
    return s[::-1]


def password_hashes(password: str):
    """returns (h_pw, h_rev_pw) as 64-byte sha3-512 digests."""
    h_pw = sha3_512(password.encode("utf-8"))
    h_rev_pw = sha3_512(reverse_str(password).encode("utf-8"))
    return h_pw, h_rev_pw


def derive_aes_key_iv_from_hash(h: bytes):
    """key = h[0:32], iv = h[32:48]. last 16 bytes are unused."""
    if len(h) != 64:
        raise ValueError("Expected a 64-byte hash for key/IV derivation")
    return h[0:AES_KEY_LEN], h[AES_KEY_LEN:AES_KEY_LEN + AES_BLOCK_SIZE]


def derive_hmac_key_from_hash(h: bytes) -> bytes:
    """first 32 bytes of the hash become the hmac key."""
    if len(h) != 64:
        raise ValueError("Expected a 64-byte hash for HMAC key derivation")
    return h[0:HMAC_KEY_LEN]


def aes_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(plaintext, AES_BLOCK_SIZE))


def aes_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """raises ValueError on bad padding (wrong key/iv)."""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES_BLOCK_SIZE)


def hmac_sha3_512(key: bytes, data: bytes) -> bytes:
    h = PyHMAC.new(key, digestmod=SHA3_512)
    h.update(data)
    return h.digest()


def hmac_verify(key: bytes, data: bytes, mac: bytes) -> bool:
    """constant-time hmac check."""
    try:
        h = PyHMAC.new(key, digestmod=SHA3_512)
        h.update(data)
        h.verify(mac)
        return True
    except (ValueError, TypeError):
        return False


def load_rsa_key_from_file(path: str):
    with open(path, "rb") as f:
        return RSA.import_key(f.read())


def rsa_encrypt(pub_key, plaintext: bytes) -> bytes:
    """oaep with sha3-512."""
    cipher = PKCS1_OAEP.new(pub_key, hashAlgo=SHA3_512)
    return cipher.encrypt(plaintext)


def rsa_decrypt(prv_key, ciphertext: bytes) -> bytes:
    cipher = PKCS1_OAEP.new(prv_key, hashAlgo=SHA3_512)
    return cipher.decrypt(ciphertext)


def rsa_sign(prv_key, data: bytes) -> bytes:
    """pkcs1v15 over sha3-512."""
    h = SHA3_512.new(data)
    return pkcs1_15.new(prv_key).sign(h)


def rsa_verify(pub_key, data: bytes, signature: bytes) -> bool:
    try:
        h = SHA3_512.new(data)
        pkcs1_15.new(pub_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False


def csprng_bytes(n: int) -> bytes:
    return get_random_bytes(n)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """read exactly n bytes or raise on eof."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("socket closed before all bytes received")
        buf.extend(chunk)
    return bytes(buf)


def send_msg(sock: socket.socket, obj: dict) -> None:
    """send dict as length-prefixed utf-8 json."""
    raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    sock.sendall(struct.pack(">I", len(raw)) + raw)


def recv_msg(sock: socket.socket) -> dict:
    """receive a length-prefixed json frame."""
    length_prefix = _recv_exact(sock, 4)
    (length,) = struct.unpack(">I", length_prefix)
    if length == 0 or length > 16 * 1024 * 1024:  # 16 mb cap
        raise ValueError(f"unreasonable frame length: {length}")
    raw = _recv_exact(sock, length)
    return json.loads(raw.decode("utf-8"))


def to_hex(b: bytes) -> str:
    return b.hex().upper()


def from_hex(h: str) -> bytes:
    return bytes.fromhex(h)


def short_hex(b: bytes, head: int = 16, tail: int = 8) -> str:
    """truncated hex for log lines — keeps first/last few bytes."""
    h = to_hex(b)
    if len(b) <= head + tail:
        return h
    return f"{h[: head * 2]}...{h[-tail * 2:]} ({len(b)} bytes)"


# enrollment payload: tight binary format to fit under rsa-3072+oaep's 254-byte limit
# layout: [1B ulen][username][64B h_pw][64B h_rev_pw][1B clen][channel]
# worst case (32B username + 7B channel) = 169 bytes

def encode_enrollment(username: str, h_pw: bytes, h_rev_pw: bytes, channel: str) -> bytes:
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
    """inverse of encode_enrollment. returns (username, h_pw, h_rev_pw, channel)."""
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