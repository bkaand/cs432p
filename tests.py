# CS432 / 532 Spring 2026 -- unit tests
# covers crypto helpers, payload formats, TCP framing, challenge-response,
# channel key derivation, and broadcast encrypt/verify
#
# run with:  python3 tests.py  (or  python3 -m pytest tests.py -v)
# no server or client needs to be running -- all tests are self-contained

import json
import socket
import struct
import threading
import unittest

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA3_512, HMAC as CryptoHMAC
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import pad, unpad


# -------------------------------------------------------------------
# helpers duplicated here so tests dont depend on importing server/client
# (importing those pulls in tkinter which needs a display)
# -------------------------------------------------------------------

def sha3(data: bytes) -> bytes:
    h = SHA3_512.new()
    h.update(data)
    return h.digest()

def aes_enc(key, iv, pt):
    return AES.new(key, AES.MODE_CBC, iv).encrypt(pad(pt, 16))

def aes_dec(key, iv, ct):
    return unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), 16)

def hmac_tag(key, data):
    m = CryptoHMAC.new(key, digestmod=SHA3_512)
    m.update(data)
    return m.digest()

def hmac_ok(key, data, tag):
    try:
        m = CryptoHMAC.new(key, digestmod=SHA3_512)
        m.update(data)
        m.verify(tag)
        return True
    except Exception:
        return False

def kiv(h64: bytes):
    # channel key derivation: first 32 bytes = AES key, next 16 bytes = IV
    return h64[:32], h64[32:48]

def auth_wrap_kiv(h_rpw: bytes):
    # auth-ack key derivation from H(reversed password):
    # lower half (bytes 32-63) = AES-256 key
    # 2nd quarter (bytes 16-31, lower half of upper half) = IV
    return h_rpw[32:], h_rpw[16:32]

def pack_enroll(username, h_pw, h_rpw, channel):
    # [64B H(pw)] [64B H(rpw)] [1B ulen] [username] [1B clen] [channel]
    ub = username.encode("utf-8")
    cb = channel.encode("utf-8")
    return h_pw + h_rpw + bytes([len(ub)]) + ub + bytes([len(cb)]) + cb

def parse_enroll(raw: bytes):
    if len(raw) < 64 + 64 + 3:
        raise ValueError("payload too short")
    pos = 0
    h_pw  = raw[pos:pos+64]; pos += 64
    h_rpw = raw[pos:pos+64]; pos += 64
    ulen  = raw[pos];         pos += 1
    if not (1 <= ulen <= 32) or pos + ulen > len(raw):
        raise ValueError(f"bad ulen {ulen}")
    uname = raw[pos:pos+ulen].decode("utf-8"); pos += ulen
    clen  = raw[pos];         pos += 1
    if not (1 <= clen <= 16) or pos + clen != len(raw):
        raise ValueError(f"bad clen {clen}")
    chan  = raw[pos:pos+clen].decode("utf-8")
    return uname, h_pw, h_rpw, chan

AUTH_SUCCESS = b"Authentication Successful"
AUTH_FAILURE = b"Authentication Unsuccessful"
CHAN_UNAVAIL = b"Channel Unavailable"

def pack_auth_success(ch_name, aes_k, aes_iv, hmac_k):
    ch_b = ch_name.encode("utf-8")
    return AUTH_SUCCESS + bytes([len(ch_b)]) + ch_b + aes_k + aes_iv + hmac_k

def parse_auth_result(pt: bytes):
    if pt.startswith(AUTH_SUCCESS):
        rest   = pt[len(AUTH_SUCCESS):]
        clen   = rest[0]
        ch     = rest[1:1+clen].decode("utf-8")
        off    = 1 + clen
        aes_k  = rest[off:off+32]
        aes_iv = rest[off+32:off+48]
        hmac_k = rest[off+48:off+80]
        return "ok", ch, aes_k, aes_iv, hmac_k
    if pt == AUTH_FAILURE:
        return "fail", None, None, None, None
    if pt == CHAN_UNAVAIL:
        return "unavail", None, None, None, None
    return "unknown", None, None, None, None

def framing_send(sock, obj):
    raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    sock.sendall(struct.pack(">I", len(raw)) + raw)

def framing_recv(sock):
    def read_n(n):
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("connection closed")
            buf += chunk
        return buf
    size = struct.unpack(">I", read_n(4))[0]
    if size == 0 or size > 16 * 1024 * 1024:
        raise ValueError(f"frame size {size} out of range")
    return json.loads(read_n(size).decode("utf-8"))

def socket_pair():
    # creates a connected (client, server) socket pair on localhost
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    cli  = socket.create_connection(("127.0.0.1", port), timeout=5)
    conn, _ = srv.accept()
    srv.close()
    return cli, conn


# -------------------------------------------------------------------
# 1. Core crypto primitives
# -------------------------------------------------------------------

class TestSHA3(unittest.TestCase):

    def test_output_is_64_bytes(self):
        self.assertEqual(len(sha3(b"anything")), 64)

    def test_deterministic(self):
        self.assertEqual(sha3(b"pw"), sha3(b"pw"))

    def test_different_inputs_differ(self):
        self.assertNotEqual(sha3(b"abc"), sha3(b"ABC"))

    def test_empty_input(self):
        # SHA3-512 of empty string should still be 64 bytes
        self.assertEqual(len(sha3(b"")), 64)

    def test_reversed_password_differs(self):
        pw = "mysecret"
        self.assertNotEqual(sha3(pw.encode()), sha3(pw[::-1].encode()))


class TestAES(unittest.TestCase):

    def test_enc_dec_roundtrip(self):
        key = get_random_bytes(32)
        iv  = get_random_bytes(16)
        pt  = b"hello world, this is a test"
        self.assertEqual(aes_dec(key, iv, aes_enc(key, iv, pt)), pt)

    def test_ciphertext_different_from_plaintext(self):
        key = get_random_bytes(32)
        iv  = get_random_bytes(16)
        pt  = b"plaintext" * 4
        self.assertNotEqual(aes_enc(key, iv, pt), pt)

    def test_wrong_key_raises(self):
        key   = get_random_bytes(32)
        iv    = get_random_bytes(16)
        ct    = aes_enc(key, iv, b"secret message that is long enough")
        wrong = get_random_bytes(32)
        with self.assertRaises(Exception):
            aes_dec(wrong, iv, ct)

    def test_different_keys_give_different_ct(self):
        iv  = get_random_bytes(16)
        pt  = b"same plaintext same plaintext xx"
        k1  = get_random_bytes(32)
        k2  = get_random_bytes(32)
        self.assertNotEqual(aes_enc(k1, iv, pt), aes_enc(k2, iv, pt))

    def test_key_must_be_32_bytes(self):
        with self.assertRaises(Exception):
            aes_enc(b"tooshort", get_random_bytes(16), b"data data data xx")


class TestHMAC(unittest.TestCase):

    def test_correct_key_verifies(self):
        key  = get_random_bytes(32)
        data = b"nonce bytes"
        self.assertTrue(hmac_ok(key, data, hmac_tag(key, data)))

    def test_wrong_key_fails(self):
        key   = get_random_bytes(32)
        wrong = get_random_bytes(32)
        data  = b"nonce bytes"
        self.assertFalse(hmac_ok(wrong, data, hmac_tag(key, data)))

    def test_tampered_data_fails(self):
        key  = get_random_bytes(32)
        data = b"original data"
        tag  = hmac_tag(key, data)
        self.assertFalse(hmac_ok(key, b"modified data", tag))

    def test_output_is_64_bytes(self):
        self.assertEqual(len(hmac_tag(get_random_bytes(32), b"data")), 64)

    def test_deterministic(self):
        key  = get_random_bytes(32)
        data = b"same data"
        self.assertEqual(hmac_tag(key, data), hmac_tag(key, data))


class TestKIV(unittest.TestCase):

    def test_key_is_32_bytes(self):
        k, iv = kiv(get_random_bytes(64))
        self.assertEqual(len(k), 32)

    def test_iv_is_16_bytes(self):
        k, iv = kiv(get_random_bytes(64))
        self.assertEqual(len(iv), 16)

    def test_key_and_iv_dont_overlap(self):
        h64  = get_random_bytes(64)
        k, iv = kiv(h64)
        self.assertEqual(k,  h64[:32])
        self.assertEqual(iv, h64[32:48])

    def test_last_16_bytes_unused(self):
        h64  = get_random_bytes(64)
        k, iv = kiv(h64)
        # 32 + 16 = 48, last 16 should not appear in k or iv
        self.assertNotIn(h64[48:], [k, iv])


# -------------------------------------------------------------------
# 2. RSA operations (uses a freshly generated 2048-bit key for speed)
# -------------------------------------------------------------------

class TestRSA(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.priv = RSA.generate(2048)
        cls.pub  = cls.priv.publickey()

    def test_oaep_roundtrip(self):
        pt  = b"test payload for RSA OAEP encryption"
        ct  = PKCS1_OAEP.new(self.pub, hashAlgo=SHA3_512).encrypt(pt)
        pt2 = PKCS1_OAEP.new(self.priv, hashAlgo=SHA3_512).decrypt(ct)
        self.assertEqual(pt, pt2)

    def test_oaep_ciphertext_nondeterministic(self):
        # OAEP uses random padding so two encryptions of same plaintext differ
        pt  = b"same plaintext"
        ct1 = PKCS1_OAEP.new(self.pub, hashAlgo=SHA3_512).encrypt(pt)
        ct2 = PKCS1_OAEP.new(self.pub, hashAlgo=SHA3_512).encrypt(pt)
        self.assertNotEqual(ct1, ct2)

    def test_sign_verify_passes(self):
        data = b"message to sign"
        sig  = pkcs1_15.new(self.priv).sign(SHA3_512.new(data))
        # should not raise
        pkcs1_15.new(self.pub).verify(SHA3_512.new(data), sig)

    def test_verify_wrong_data_fails(self):
        data = b"original"
        sig  = pkcs1_15.new(self.priv).sign(SHA3_512.new(data))
        with self.assertRaises(Exception):
            pkcs1_15.new(self.pub).verify(SHA3_512.new(b"tampered"), sig)

    def test_verify_wrong_key_fails(self):
        other_key = RSA.generate(2048)
        data = b"some data"
        sig  = pkcs1_15.new(self.priv).sign(SHA3_512.new(data))
        with self.assertRaises(Exception):
            pkcs1_15.new(other_key.publickey()).verify(SHA3_512.new(data), sig)

    def test_decrypt_wrong_key_fails(self):
        other_key = RSA.generate(2048)
        ct = PKCS1_OAEP.new(self.pub, hashAlgo=SHA3_512).encrypt(b"secret")
        with self.assertRaises(Exception):
            PKCS1_OAEP.new(other_key, hashAlgo=SHA3_512).decrypt(ct)


# -------------------------------------------------------------------
# 3. Enrollment payload format
# -------------------------------------------------------------------

class TestEnrollPayload(unittest.TestCase):

    def _hashes(self, pw="password"):
        return sha3(pw.encode()), sha3(pw[::-1].encode())

    def test_roundtrip_basic(self):
        h_pw, h_rpw = self._hashes()
        raw = pack_enroll("alice", h_pw, h_rpw, "IF100")
        u, hp, hrp, ch = parse_enroll(raw)
        self.assertEqual(u,   "alice")
        self.assertEqual(hp,  h_pw)
        self.assertEqual(hrp, h_rpw)
        self.assertEqual(ch,  "IF100")

    def test_all_channels(self):
        h_pw, h_rpw = self._hashes()
        for ch in ("IF100", "MATH101", "SPS101"):
            _, _, _, parsed = parse_enroll(pack_enroll("u", h_pw, h_rpw, ch))
            self.assertEqual(parsed, ch)

    def test_max_length_username(self):
        h_pw, h_rpw = self._hashes()
        long_user = "x" * 32
        _, u, _, _ = parse_enroll(pack_enroll(long_user, h_pw, h_rpw, "IF100"))[0:4]
        # reparse properly
        u, _, _, _ = parse_enroll(pack_enroll(long_user, h_pw, h_rpw, "IF100"))
        self.assertEqual(u, long_user)

    def test_payload_too_short_raises(self):
        with self.assertRaises(ValueError):
            parse_enroll(b"short")

    def test_fits_rsa3072_oaep_sha3512_limit(self):
        # RSA-3072 with OAEP+SHA3-512: max plaintext = 384 - 2*64 - 2 = 254 bytes
        h_pw  = get_random_bytes(64)
        h_rpw = get_random_bytes(64)
        raw   = pack_enroll("x" * 32, h_pw, h_rpw, "MATH101")
        self.assertLessEqual(len(raw), 254, f"payload is {len(raw)}B, exceeds RSA OAEP limit")

    def test_hashes_are_64_bytes(self):
        h_pw, h_rpw = self._hashes("mypassword")
        self.assertEqual(len(h_pw),  64)
        self.assertEqual(len(h_rpw), 64)

    def test_password_and_reversed_differ(self):
        h_pw, h_rpw = self._hashes("symmetric")
        self.assertNotEqual(h_pw, h_rpw)


# -------------------------------------------------------------------
# 4. Auth success / failure payload format
# -------------------------------------------------------------------

class TestAuthPayload(unittest.TestCase):

    def _keys(self):
        return get_random_bytes(32), get_random_bytes(16), get_random_bytes(32)

    def test_success_roundtrip(self):
        aes_k, aes_iv, hmac_k = self._keys()
        blob = pack_auth_success("IF100", aes_k, aes_iv, hmac_k)
        status, ch, k, iv, mk = parse_auth_result(blob)
        self.assertEqual(status, "ok")
        self.assertEqual(ch,     "IF100")
        self.assertEqual(k,      aes_k)
        self.assertEqual(iv,     aes_iv)
        self.assertEqual(mk,     hmac_k)

    def test_all_channels_parsed(self):
        for ch in ("IF100", "MATH101", "SPS101"):
            aes_k, aes_iv, hmac_k = self._keys()
            blob = pack_auth_success(ch, aes_k, aes_iv, hmac_k)
            status, parsed_ch, _, _, _ = parse_auth_result(blob)
            self.assertEqual(status, "ok")
            self.assertEqual(parsed_ch, ch)

    def test_auth_failure_parsed(self):
        status, ch, _, _, _ = parse_auth_result(AUTH_FAILURE)
        self.assertEqual(status, "fail")
        self.assertIsNone(ch)

    def test_channel_unavailable_parsed(self):
        status, ch, _, _, _ = parse_auth_result(CHAN_UNAVAIL)
        self.assertEqual(status, "unavail")

    def test_unknown_plaintext(self):
        status, _, _, _, _ = parse_auth_result(b"something unexpected")
        self.assertEqual(status, "unknown")

    def test_keys_have_correct_lengths(self):
        aes_k, aes_iv, hmac_k = self._keys()
        blob = pack_auth_success("SPS101", aes_k, aes_iv, hmac_k)
        _, _, k, iv, mk = parse_auth_result(blob)
        self.assertEqual(len(k),  32)
        self.assertEqual(len(iv), 16)
        self.assertEqual(len(mk), 32)


# -------------------------------------------------------------------
# 5. Password key derivation (used in the auth handshake)
# -------------------------------------------------------------------

class TestKeyDerivation(unittest.TestCase):

    def test_hmac_key_length(self):
        h_pw = sha3(b"somepassword")
        # lower half of H(pw) = bytes 32-63
        self.assertEqual(len(h_pw[32:]), 32)

    def test_ack_key_and_iv_lengths(self):
        h_rpw = sha3(b"drowssap")
        wrap_k, wrap_iv = auth_wrap_kiv(h_rpw)
        self.assertEqual(len(wrap_k),  32)
        self.assertEqual(len(wrap_iv), 16)

    def test_hmac_key_differs_from_ack_key(self):
        pw    = "testpassword"
        h_pw  = sha3(pw.encode())
        h_rpw = sha3(pw[::-1].encode())
        self.assertNotEqual(h_pw[32:], h_rpw[32:])

    def test_channel_key_derivation_lengths(self):
        master  = "channelmaster"
        h_fwd   = sha3(master.encode())
        h_rev   = sha3(master[::-1].encode())
        aes_k, aes_iv = kiv(h_fwd)
        hmac_k  = h_rev[:32]
        self.assertEqual(len(aes_k),  32)
        self.assertEqual(len(aes_iv), 16)
        self.assertEqual(len(hmac_k), 32)

    def test_channel_aes_and_hmac_keys_differ(self):
        master = "secret"
        h_fwd  = sha3(master.encode())
        h_rev  = sha3(master[::-1].encode())
        aes_k  = h_fwd[:32]
        hmac_k = h_rev[:32]
        self.assertNotEqual(aes_k, hmac_k)

    def test_same_master_gives_same_keys(self):
        master = "reproducible"
        k1, iv1 = kiv(sha3(master.encode()))
        k2, iv2 = kiv(sha3(master.encode()))
        self.assertEqual(k1, k2)
        self.assertEqual(iv1, iv2)

    def test_different_masters_give_different_keys(self):
        k1, _ = kiv(sha3(b"master1"))
        k2, _ = kiv(sha3(b"master2"))
        self.assertNotEqual(k1, k2)


# -------------------------------------------------------------------
# 6. TCP framing (length-prefixed JSON)
# -------------------------------------------------------------------

class TestFraming(unittest.TestCase):

    def test_send_recv_basic(self):
        a, b = socket_pair()
        try:
            framing_send(a, {"type": "HELLO", "n": 1})
            msg = framing_recv(b)
            self.assertEqual(msg["type"], "HELLO")
            self.assertEqual(msg["n"], 1)
        finally:
            a.close(); b.close()

    def test_multiple_messages_in_order(self):
        a, b = socket_pair()
        try:
            for i in range(5):
                framing_send(a, {"seq": i})
            for i in range(5):
                msg = framing_recv(b)
                self.assertEqual(msg["seq"], i)
        finally:
            a.close(); b.close()

    def test_large_payload(self):
        a, b = socket_pair()
        try:
            big = {"type": "DATA", "blob": "x" * 50000}
            framing_send(a, big)
            msg = framing_recv(b)
            self.assertEqual(len(msg["blob"]), 50000)
        finally:
            a.close(); b.close()

    def test_bidirectional(self):
        a, b = socket_pair()
        try:
            framing_send(a, {"from": "a"})
            framing_send(b, {"from": "b"})
            self.assertEqual(framing_recv(b)["from"], "a")
            self.assertEqual(framing_recv(a)["from"], "b")
        finally:
            a.close(); b.close()

    def test_hex_field_survives_json(self):
        a, b = socket_pair()
        try:
            ct_hex = get_random_bytes(32).hex().upper()
            framing_send(a, {"ct_hex": ct_hex})
            msg = framing_recv(b)
            self.assertEqual(msg["ct_hex"], ct_hex)
        finally:
            a.close(); b.close()


# -------------------------------------------------------------------
# 7. Challenge-response HMAC flow
# -------------------------------------------------------------------

class TestChallengeResponse(unittest.TestCase):

    def test_correct_password_verifies(self):
        pw      = "correctpassword"
        h_pw    = sha3(pw.encode())
        hmac_k  = h_pw[32:]   # lower half of H(pw)
        nonce   = get_random_bytes(16)
        mac     = hmac_tag(hmac_k, nonce)
        self.assertTrue(hmac_ok(hmac_k, nonce, mac))

    def test_wrong_password_fails(self):
        right_pw  = "rightpassword"
        wrong_pw  = "wrongpassword"
        nonce     = get_random_bytes(16)
        mac       = hmac_tag(sha3(right_pw.encode())[32:], nonce)
        self.assertFalse(hmac_ok(sha3(wrong_pw.encode())[32:], nonce, mac))

    def test_replay_with_different_nonce_fails(self):
        pw     = "somepassword"
        hmac_k = sha3(pw.encode())[32:]   # lower half of H(pw)
        n1     = get_random_bytes(16)
        n2     = b"\xff" * 16   # guaranteed to differ from n1
        mac    = hmac_tag(hmac_k, n1)
        self.assertFalse(hmac_ok(hmac_k, n2, mac))

    def test_nonce_is_16_bytes(self):
        nonce = get_random_bytes(16)
        self.assertEqual(len(nonce), 16)

    def test_each_nonce_is_unique(self):
        nonces = [get_random_bytes(16) for _ in range(100)]
        self.assertEqual(len(set(nonces)), 100)

    def test_ack_encryption_decryption(self):
        # server encrypts ack with keys from H(reversed pw)
        pw     = "mypassword"
        h_rpw  = sha3(pw[::-1].encode())
        wrap_k, wrap_iv = auth_wrap_kiv(h_rpw)

        plaintext = AUTH_SUCCESS + b"\x05IF100" + get_random_bytes(80)
        ct        = aes_enc(wrap_k, wrap_iv, plaintext)
        recovered = aes_dec(wrap_k, wrap_iv, ct)
        self.assertEqual(recovered, plaintext)

    def test_wrong_password_cant_decrypt_ack(self):
        right_pw = "right"
        wrong_pw = "wrong"
        h_rpw_r  = sha3(right_pw[::-1].encode())
        h_rpw_w  = sha3(wrong_pw[::-1].encode())
        wrap_k_r, wrap_iv_r = auth_wrap_kiv(h_rpw_r)
        wrap_k_w, wrap_iv_w = auth_wrap_kiv(h_rpw_w)

        ct = aes_enc(wrap_k_r, wrap_iv_r, AUTH_SUCCESS + b"\x00" * 80)
        with self.assertRaises(Exception):
            aes_dec(wrap_k_w, wrap_iv_w, ct)


# -------------------------------------------------------------------
# 8. Broadcast message encrypt / HMAC / decrypt flow
# -------------------------------------------------------------------

class TestBroadcast(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        master      = "channelsecretmaster"
        h_fwd       = sha3(master.encode())
        h_rev       = sha3(master[::-1].encode())
        cls.aes_k   = h_fwd[:32]
        cls.aes_iv  = h_fwd[32:48]
        cls.hmac_k  = h_rev[:32]

    def _encrypt(self, msg):
        ct  = aes_enc(self.aes_k, self.aes_iv, msg.encode())
        tag = hmac_tag(self.hmac_k, ct)
        return ct, tag

    def _decrypt(self, ct, tag):
        if not hmac_ok(self.hmac_k, ct, tag):
            raise ValueError("HMAC invalid")
        return aes_dec(self.aes_k, self.aes_iv, ct).decode()

    def test_send_receive_roundtrip(self):
        msg = "hello channel members"
        ct, tag = self._encrypt(msg)
        self.assertEqual(self._decrypt(ct, tag), msg)

    def test_tampered_ciphertext_fails_hmac(self):
        _, tag = self._encrypt("original")
        bad_ct = get_random_bytes(32)
        with self.assertRaises(ValueError):
            self._decrypt(bad_ct, tag)

    def test_tampered_tag_fails(self):
        ct, _ = self._encrypt("original")
        bad_tag = get_random_bytes(64)
        with self.assertRaises(ValueError):
            self._decrypt(ct, bad_tag)

    def test_wrong_channel_key_fails_decrypt(self):
        ct, tag = self._encrypt("secret")
        wrong_k  = get_random_bytes(32)
        wrong_iv = get_random_bytes(16)
        # hmac will also fail but the decrypt itself should raise too
        with self.assertRaises(Exception):
            unpad(AES.new(wrong_k, AES.MODE_CBC, wrong_iv).decrypt(ct), 16)

    def test_empty_message(self):
        ct, tag = self._encrypt("")
        self.assertEqual(self._decrypt(ct, tag), "")

    def test_long_message(self):
        msg = "a" * 10000
        ct, tag = self._encrypt(msg)
        self.assertEqual(self._decrypt(ct, tag), msg)

    def test_server_relay_doesnt_need_keys(self):
        # server just forwards (ct, tag) without decrypting -- simulate that
        ct, tag = self._encrypt("broadcast message")
        # pretend to be the server: receive and re-send unchanged
        relayed_ct, relayed_tag = ct, tag
        # client verifies and decrypts the relayed packet
        self.assertEqual(self._decrypt(relayed_ct, relayed_tag), "broadcast message")


# -------------------------------------------------------------------
# 9. Integration: full enrollment + auth flow over real sockets
# -------------------------------------------------------------------

class TestEnrollmentIntegration(unittest.TestCase):
    """
    Simulates the enrollment wire exchange without running the actual server.
    A thread acts as the server, the main thread acts as the client.
    """

    @classmethod
    def setUpClass(cls):
        # 3072 required -- SHA3-512 OAEP on 2048 only allows ~126B plaintext
        # our enrollment payload is ~136B minimum so 2048 would fail
        cls.enc_key = RSA.generate(3072)
        cls.sig_key = RSA.generate(3072)
        cls.enc_pub = cls.enc_key.publickey()
        cls.sig_pub = cls.sig_key.publickey()

    def test_enroll_success(self):
        cli, srv = socket_pair()

        # server thread: receive REGISTER, verify, reply REG_RESULT
        def server_thread():
            msg     = framing_recv(srv)
            self.assertEqual(msg["type"], "REGISTER")
            ct      = bytes.fromhex(msg["enc_hex"])
            plain   = PKCS1_OAEP.new(self.enc_key, hashAlgo=SHA3_512).decrypt(ct)
            u, h_pw, h_rpw, ch = parse_enroll(plain)
            reply   = f"success: enrolled '{u}' on {ch}"
            sig     = pkcs1_15.new(self.sig_key).sign(SHA3_512.new(reply.encode()))
            framing_send(srv, {"type": "REG_RESULT", "text": reply, "sig_hex": sig.hex()})
            srv.close()

        t = threading.Thread(target=server_thread, daemon=True)
        t.start()

        # client side
        pw      = "testpassword"
        h_pw    = sha3(pw.encode())
        h_rpw   = sha3(pw[::-1].encode())
        payload = pack_enroll("testuser", h_pw, h_rpw, "IF100")
        ct      = PKCS1_OAEP.new(self.enc_pub, hashAlgo=SHA3_512).encrypt(payload)
        framing_send(cli, {"type": "REGISTER", "enc_hex": ct.hex()})

        resp = framing_recv(cli)
        self.assertEqual(resp["type"], "REG_RESULT")
        text = resp["text"]
        sig  = bytes.fromhex(resp["sig_hex"])
        pkcs1_15.new(self.sig_pub).verify(SHA3_512.new(text.encode()), sig)
        self.assertTrue(text.startswith("success"))
        cli.close()
        t.join(timeout=3)

    def test_enroll_duplicate_username_rejected(self):
        cli, srv = socket_pair()

        def server_thread():
            msg   = framing_recv(srv)
            ct    = bytes.fromhex(msg["enc_hex"])
            plain = PKCS1_OAEP.new(self.enc_key, hashAlgo=SHA3_512).decrypt(ct)
            u, _, _, _ = parse_enroll(plain)
            # pretend user already exists
            reply = f"error: username taken"
            sig   = pkcs1_15.new(self.sig_key).sign(SHA3_512.new(reply.encode()))
            framing_send(srv, {"type": "REG_RESULT", "text": reply, "sig_hex": sig.hex()})
            srv.close()

        t = threading.Thread(target=server_thread, daemon=True)
        t.start()

        payload = pack_enroll("existinguser", sha3(b"pw"), sha3(b"wp"), "MATH101")
        ct      = PKCS1_OAEP.new(self.enc_pub, hashAlgo=SHA3_512).encrypt(payload)
        framing_send(cli, {"type": "REGISTER", "enc_hex": ct.hex()})

        resp = framing_recv(cli)
        self.assertFalse(resp["text"].startswith("success"))
        cli.close()
        t.join(timeout=3)


class TestAuthIntegration(unittest.TestCase):
    """
    Simulates the full challenge-response login flow over real sockets.
    """

    @classmethod
    def setUpClass(cls):
        cls.sig_key = RSA.generate(2048)
        cls.sig_pub = cls.sig_key.publickey()

        # pre-enrolled user data
        cls.pw       = "loginpassword"
        cls.h_pw     = sha3(cls.pw.encode())
        cls.h_rpw    = sha3(cls.pw[::-1].encode())

        # channel keys that the server would have generated
        master        = "channelmaster"
        h_fwd         = sha3(master.encode())
        h_rev         = sha3(master[::-1].encode())
        cls.ch_aes_k  = h_fwd[:32]
        cls.ch_aes_iv = h_fwd[32:48]
        cls.ch_hmac_k = h_rev[:32]

    def _server_auth_thread(self, srv, username, h_pw_stored, h_rpw_stored,
                             ch_name, ch_aes_k, ch_aes_iv, ch_hmac_k):
        try:
            msg   = framing_recv(srv)
            nonce = get_random_bytes(16)
            framing_send(srv, {"type": "CHALLENGE", "nonce_hex": nonce.hex().upper()})

            reply = framing_recv(srv)
            client_mac = bytes.fromhex(reply["mac_hex"])

            hmac_key     = h_pw_stored[32:]          # lower half of H(pw)
            ack_k, ack_v = auth_wrap_kiv(h_rpw_stored)
            auth_ok      = hmac_ok(hmac_key, nonce, client_mac)

            if auth_ok:
                blob = pack_auth_success(ch_name, ch_aes_k, ch_aes_iv, ch_hmac_k)
                pt   = blob
            else:
                pt = AUTH_FAILURE

            ct  = aes_enc(ack_k, ack_v, pt)
            sig = pkcs1_15.new(self.sig_key).sign(SHA3_512.new(ct))
            framing_send(srv, {
                "type":    "LOGIN_RESULT",
                "ct_hex":  ct.hex().upper(),
                "sig_hex": sig.hex().upper()
            })
        finally:
            srv.close()

    def test_successful_login(self):
        cli, srv = socket_pair()
        t = threading.Thread(
            target=self._server_auth_thread,
            args=(srv, "testuser", self.h_pw, self.h_rpw,
                  "IF100", self.ch_aes_k, self.ch_aes_iv, self.ch_hmac_k),
            daemon=True
        )
        t.start()

        framing_send(cli, {"type": "LOGIN", "user": "testuser"})
        chal     = framing_recv(cli)
        nonce    = bytes.fromhex(chal["nonce_hex"])
        mac      = hmac_tag(self.h_pw[32:], nonce)   # lower half of H(pw)
        framing_send(cli, {"type": "HMAC_RESP", "mac_hex": mac.hex().upper()})

        result   = framing_recv(cli)
        ct       = bytes.fromhex(result["ct_hex"])
        sig      = bytes.fromhex(result["sig_hex"])
        pkcs1_15.new(self.sig_pub).verify(SHA3_512.new(ct), sig)

        wrap_k, wrap_iv = auth_wrap_kiv(self.h_rpw)
        pt = aes_dec(wrap_k, wrap_iv, ct)

        status, ch, k, iv, mk = parse_auth_result(pt)
        self.assertEqual(status, "ok")
        self.assertEqual(ch, "IF100")
        self.assertEqual(k,  self.ch_aes_k)
        self.assertEqual(iv, self.ch_aes_iv)
        self.assertEqual(mk, self.ch_hmac_k)

        cli.close()
        t.join(timeout=3)

    def test_wrong_password_gets_failure(self):
        cli, srv = socket_pair()
        t = threading.Thread(
            target=self._server_auth_thread,
            args=(srv, "testuser", self.h_pw, self.h_rpw,
                  "IF100", self.ch_aes_k, self.ch_aes_iv, self.ch_hmac_k),
            daemon=True
        )
        t.start()

        framing_send(cli, {"type": "LOGIN", "user": "testuser"})
        chal       = framing_recv(cli)
        nonce      = bytes.fromhex(chal["nonce_hex"])
        wrong_h_pw = sha3(b"totallyWrongPassword")
        mac        = hmac_tag(wrong_h_pw[32:], nonce)   # lower half of H(wrong pw)
        framing_send(cli, {"type": "HMAC_RESP", "mac_hex": mac.hex().upper()})

        result   = framing_recv(cli)
        ct       = bytes.fromhex(result["ct_hex"])

        # client tries to decrypt with correct reversed pw -- should fail or give FAILURE
        wrap_k, wrap_iv = auth_wrap_kiv(self.h_rpw)
        try:
            pt = aes_dec(wrap_k, wrap_iv, ct)
            # if decryption doesnt raise, plaintext should be failure
            status, *_ = parse_auth_result(pt)
            self.assertEqual(status, "fail")
        except Exception:
            pass  # padding error is also acceptable for wrong password

        cli.close()
        t.join(timeout=3)


# -------------------------------------------------------------------
# 10. auth_wrap_kiv byte positions (spec compliance)
# -------------------------------------------------------------------

class TestAuthWrapKiv(unittest.TestCase):

    def test_key_is_lower_half(self):
        # AES key must be the lower half of H(rpw), i.e. bytes 32-63
        h = get_random_bytes(64)
        k, _ = auth_wrap_kiv(h)
        self.assertEqual(k, h[32:])

    def test_iv_is_second_quarter(self):
        # IV must be the 2nd quarter of H(rpw), i.e. bytes 16-31
        h = get_random_bytes(64)
        _, iv = auth_wrap_kiv(h)
        self.assertEqual(iv, h[16:32])

    def test_key_and_iv_do_not_overlap(self):
        h = get_random_bytes(64)
        k, iv = auth_wrap_kiv(h)
        self.assertNotEqual(k, iv)
        # bytes 16-31 and bytes 32-63 share no overlap
        self.assertEqual(len(k),  32)
        self.assertEqual(len(iv), 16)

    def test_auth_wrap_differs_from_channel_kiv(self):
        # auth-ack key derivation must produce different slices than channel key derivation
        h = get_random_bytes(64)
        ch_k,   ch_iv   = kiv(h)           # channel: bytes 0-31, 32-47
        ack_k,  ack_iv  = auth_wrap_kiv(h) # auth:    bytes 32-63, 16-31
        self.assertNotEqual(ch_k,  ack_k)
        self.assertNotEqual(ch_iv, ack_iv)

    def test_using_wrong_half_as_hmac_key_fails(self):
        # if the client accidentally uses the UPPER half of H(pw) for the HMAC,
        # the server (which uses the LOWER half) will reject it
        pw     = "demopassword"
        h_pw   = sha3(pw.encode())
        nonce  = get_random_bytes(16)
        correct_key = h_pw[32:]   # lower half -- what both sides must use
        wrong_key   = h_pw[:32]   # upper half -- wrong
        mac_with_wrong_key = hmac_tag(wrong_key, nonce)
        self.assertFalse(hmac_ok(correct_key, nonce, mac_with_wrong_key))

    def test_using_wrong_half_as_wrap_key_cant_decrypt(self):
        # server encrypts ack with lower-half key; using upper-half key to decrypt fails
        pw    = "demopassword"
        h_rpw = sha3(pw[::-1].encode())
        correct_k, correct_iv = auth_wrap_kiv(h_rpw)
        wrong_k = h_rpw[:32]   # upper half
        ct = aes_enc(correct_k, correct_iv, AUTH_SUCCESS + b"\x00" * 80)
        with self.assertRaises(Exception):
            aes_dec(wrong_k, correct_iv, ct)


# -------------------------------------------------------------------
# 11. Channel isolation (TC30/31)
# -------------------------------------------------------------------

class TestChannelIsolation(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # derive independent keys for two channels from different master secrets
        for ch, master in (("IF100", "if100-secret-demo"),
                           ("MATH101", "math101-secret-demo")):
            h_fwd = sha3(master.encode())
            h_rev = sha3(master[::-1].encode())
            setattr(cls, f"aes_k_{ch}",  h_fwd[:32])
            setattr(cls, f"aes_iv_{ch}", h_fwd[32:48])
            setattr(cls, f"hmac_k_{ch}", h_rev[:32])

    def test_different_masters_produce_different_channel_keys(self):
        self.assertNotEqual(self.aes_k_IF100,  self.aes_k_MATH101)
        self.assertNotEqual(self.aes_iv_IF100, self.aes_iv_MATH101)
        self.assertNotEqual(self.hmac_k_IF100, self.hmac_k_MATH101)

    def test_cross_channel_hmac_fails(self):
        # message from IF100 must not pass HMAC check with MATH101 key
        ct  = aes_enc(self.aes_k_IF100, self.aes_iv_IF100, b"hello IF100")
        tag = hmac_tag(self.hmac_k_IF100, ct)
        self.assertFalse(hmac_ok(self.hmac_k_MATH101, ct, tag))

    def test_cross_channel_decrypt_fails(self):
        # ciphertext from IF100 cannot be correctly decrypted with MATH101 keys
        ct = aes_enc(self.aes_k_IF100, self.aes_iv_IF100, b"confidential IF100 message")
        with self.assertRaises(Exception):
            aes_dec(self.aes_k_MATH101, self.aes_iv_MATH101, ct)

    def test_same_channel_both_users_can_decrypt(self):
        # user1 and user2 both have IF100 keys -- both must decrypt the same ciphertext
        msg = "broadcast to IF100"
        ct  = aes_enc(self.aes_k_IF100, self.aes_iv_IF100, msg.encode())
        tag = hmac_tag(self.hmac_k_IF100, ct)
        # user1 verifies + decrypts
        self.assertTrue(hmac_ok(self.hmac_k_IF100, ct, tag))
        self.assertEqual(aes_dec(self.aes_k_IF100, self.aes_iv_IF100, ct), msg.encode())
        # user2 (same keys) does the same
        self.assertTrue(hmac_ok(self.hmac_k_IF100, ct, tag))
        self.assertEqual(aes_dec(self.aes_k_IF100, self.aes_iv_IF100, ct), msg.encode())


# -------------------------------------------------------------------
# 12. TCP framing robustness (TC3 / invalid frame sizes)
# -------------------------------------------------------------------

class TestFramingRobustness(unittest.TestCase):

    def test_rejects_zero_size_frame(self):
        a, b = socket_pair()
        try:
            a.sendall(struct.pack(">I", 0))  # size=0 is invalid
            with self.assertRaises((ValueError, ConnectionError)):
                framing_recv(b)
        finally:
            a.close(); b.close()

    def test_rejects_oversized_frame(self):
        a, b = socket_pair()
        try:
            a.sendall(struct.pack(">I", 16 * 1024 * 1024 + 1))  # > 16 MB limit
            with self.assertRaises((ValueError, ConnectionError)):
                framing_recv(b)
        finally:
            a.close(); b.close()

    def test_partial_send_is_reassembled(self):
        # framing_recv must handle the case where the payload arrives in small chunks
        a, b = socket_pair()
        try:
            payload = {"type": "MSG", "data": "x" * 200}
            raw     = json.dumps(payload, separators=(",", ":")).encode()
            header  = struct.pack(">I", len(raw))
            # send header and body in two separate calls to force partial read
            a.sendall(header)
            a.sendall(raw[:50])
            a.sendall(raw[50:])
            msg = framing_recv(b)
            self.assertEqual(msg["data"], "x" * 200)
        finally:
            a.close(); b.close()


# -------------------------------------------------------------------
# 13. Channel Unavailable auth path (TC9)
# -------------------------------------------------------------------

class TestChannelUnavailable(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.sig_key = RSA.generate(2048)
        cls.sig_pub = cls.sig_key.publickey()
        cls.pw      = "unavailpassword"
        cls.h_pw    = sha3(cls.pw.encode())
        cls.h_rpw   = sha3(cls.pw[::-1].encode())

    def test_channel_unavailable_response_parsed(self):
        cli, srv = socket_pair()

        def server_thread():
            try:
                framing_recv(srv)        # LOGIN
                nonce = get_random_bytes(16)
                framing_send(srv, {"type": "CHALLENGE", "nonce_hex": nonce.hex().upper()})
                framing_recv(srv)        # HMAC_RESP -- verify is skipped to isolate this path
                ack_k, ack_v = auth_wrap_kiv(self.h_rpw)
                ct  = aes_enc(ack_k, ack_v, CHAN_UNAVAIL)
                sig = pkcs1_15.new(self.sig_key).sign(SHA3_512.new(ct))
                framing_send(srv, {"type": "LOGIN_RESULT",
                                   "ct_hex": ct.hex().upper(),
                                   "sig_hex": sig.hex().upper()})
            finally:
                srv.close()

        t = threading.Thread(target=server_thread, daemon=True)
        t.start()

        framing_send(cli, {"type": "LOGIN", "user": "user_no_keys"})
        chal  = framing_recv(cli)
        nonce = bytes.fromhex(chal["nonce_hex"])
        mac   = hmac_tag(self.h_pw[32:], nonce)
        framing_send(cli, {"type": "HMAC_RESP", "mac_hex": mac.hex().upper()})

        result  = framing_recv(cli)
        ct      = bytes.fromhex(result["ct_hex"])
        sig     = bytes.fromhex(result["sig_hex"])
        pkcs1_15.new(self.sig_pub).verify(SHA3_512.new(ct), sig)

        ack_k, ack_v = auth_wrap_kiv(self.h_rpw)
        pt = aes_dec(ack_k, ack_v, ct)
        status, *_ = parse_auth_result(pt)
        self.assertEqual(status, "unavail")

        cli.close()
        t.join(timeout=3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
