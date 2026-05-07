"""
secure channel client — cs432 project
enrollment, auth, broadcast recv/send + tkinter gui
"""

import json
import queue
import socket
import struct
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA3_512, HMAC as PyHMAC
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import pad, unpad


# --- constants ---
CHANNELS = ("IF100", "MATH101", "SPS101")

AES_BLOCK_SIZE = 16
AES_KEY_LEN = 32
HMAC_KEY_LEN = 32
NONCE_LEN = 16

AUTH_OK_TEXT = b"Authentication Successful"
AUTH_FAIL_TEXT = b"Authentication Unsuccessful"
AUTH_CHANNEL_UNAVAILABLE = b"Channel Unavailable"


# --- crypto helpers ---
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


def rsa_verify(pub_key, data: bytes, signature: bytes) -> bool:
    try:
        h = SHA3_512.new(data)
        pkcs1_15.new(pub_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False


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
    if length == 0 or length > 16 * 1024 * 1024:
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


def encode_enrollment(username: str, h_pw: bytes, h_rev_pw: bytes, channel: str) -> bytes:
    """tight binary format to fit under rsa-3072+oaep's 254-byte limit."""
    if len(h_pw) != 64 or len(h_rev_pw) != 64:
        raise ValueError("Password hashes must be 64 bytes (SHA3-512)")
    u = username.encode("utf-8")
    c = channel.encode("utf-8")
    if not (1 <= len(u) <= 32):
        raise ValueError("Username must be 1-32 UTF-8 bytes")
    if not (1 <= len(c) <= 16):
        raise ValueError("Channel name must be 1-16 UTF-8 bytes")
    return bytes([len(u)]) + u + h_pw + h_rev_pw + bytes([len(c)]) + c


# --- client core ---
class SecureChannelClient:
    """
    holds state for one client session. gui calls in,
    we report back via log_cb / state_cb / message_cb.
    """

    def __init__(self, log_cb, state_cb, message_cb):
        self.log_cb = log_cb
        self.state_cb = state_cb
        self.message_cb = message_cb

        # server pubkeys, loaded from pem files
        self.server_enc_pub = None      # encrypt to server
        self.server_sign_pub = None     # verify server sigs

        # session state
        self.sock = None
        self.username = None
        self.channel = None
        self.session_aes_key = None
        self.session_iv = None
        self.session_hmac_key = None

        self._recv_thread = None
        self._connected = False

    def load_server_pubkeys(self, enc_path: str, sign_path: str) -> None:
        self.server_enc_pub = load_rsa_key_from_file(enc_path)
        self.server_sign_pub = load_rsa_key_from_file(sign_path)
        self.log_cb(f"Loaded server enc public key from: {enc_path}")
        self.log_cb(f"  modulus n (hex): {to_hex(self.server_enc_pub.n.to_bytes(384, 'big'))}")
        self.log_cb(f"  public  e (hex): {to_hex(self.server_enc_pub.e.to_bytes((self.server_enc_pub.e.bit_length() + 7) // 8, 'big'))}")
        self.log_cb(f"Loaded server sign public key from: {sign_path}")
        self.log_cb(f"  modulus n (hex): {to_hex(self.server_sign_pub.n.to_bytes(384, 'big'))}")
        self.log_cb(f"  public  e (hex): {to_hex(self.server_sign_pub.e.to_bytes((self.server_sign_pub.e.bit_length() + 7) // 8, 'big'))}")

    def enroll(self, ip: str, port: int, username: str, password: str, channel: str) -> bool:
        """enroll the user. returns True if it worked."""
        if self.server_enc_pub is None or self.server_sign_pub is None:
            self.log_cb("ERROR: Server public keys not loaded.")
            return False
        if channel not in CHANNELS:
            self.log_cb(f"ERROR: invalid channel: {channel}")
            return False

        h_pw, h_rev_pw = password_hashes(password)
        self.log_cb(f"[Enrollment] SHA3-512(password):           {to_hex(h_pw)}")
        self.log_cb(f"[Enrollment] SHA3-512(reversed password):  {to_hex(h_rev_pw)}")

        payload = encode_enrollment(username, h_pw, h_rev_pw, channel)

        ct = rsa_encrypt(self.server_enc_pub, payload)
        self.log_cb(f"[Enrollment] RSA-OAEP encrypted payload: {short_hex(ct)}")

        try:
            sock = socket.create_connection((ip, port), timeout=10)
        except OSError as e:
            self.log_cb(f"[Enrollment] Connection failed: {e}")
            return False

        try:
            send_msg(sock, {"type": "ENROLL_REQ", "payload_hex": to_hex(ct)})
            resp = recv_msg(sock)
        except (ConnectionError, OSError, ValueError) as e:
            self.log_cb(f"[Enrollment] Network error: {e}")
            try: sock.close()
            except OSError: pass
            return False
        finally:
            try: sock.close()
            except OSError: pass

        if resp.get("type") != "ENROLL_RESP":
            self.log_cb(f"[Enrollment] Unexpected response: {resp}")
            return False

        message = resp.get("message", "")
        sig = from_hex(resp.get("signature_hex", ""))
        self.log_cb(f"[Enrollment] Server response: '{message}'")
        self.log_cb(f"[Enrollment] Signature: {short_hex(sig)}")

        if not rsa_verify(self.server_sign_pub, message.encode("utf-8"), sig):
            self.log_cb("[Enrollment] SIGNATURE INVALID. Discarding response.")
            return False
        self.log_cb("[Enrollment] Server signature verified OK.")

        if message.startswith("success"):
            return True
        return False

    def login(self, ip: str, port: int, username: str, password: str) -> str:
        """
        challenge-response auth. returns "ok", "wrong_password",
        "auth_failed", "channel_unavailable", or "network_error".
        on "ok" the socket stays open and recv thread is started.
        """
        if self.server_enc_pub is None or self.server_sign_pub is None:
            self.log_cb("ERROR: Server public keys not loaded.")
            return "network_error"

        try:
            sock = socket.create_connection((ip, port), timeout=10)
        except OSError as e:
            self.log_cb(f"[Auth] Connection failed: {e}")
            return "network_error"

        try:
            self.log_cb(f"[Auth] Sending AUTH_REQ for username '{username}'")
            send_msg(sock, {"type": "AUTH_REQ", "username": username})

            chal_msg = recv_msg(sock)
            if chal_msg.get("type") != "AUTH_CHALLENGE":
                self.log_cb(f"[Auth] Unexpected: {chal_msg}")
                sock.close()
                return "network_error"

            challenge = from_hex(chal_msg["challenge_hex"])
            self.log_cb(f"[Auth] Received 128-bit challenge: {to_hex(challenge)}")

            h_pw, h_rev_pw = password_hashes(password)
            hmac_key = derive_hmac_key_from_hash(h_pw)
            mac = hmac_sha3_512(hmac_key, challenge)
            self.log_cb(f"[Auth] HMAC key (lower half h(pw)): {to_hex(hmac_key)}")
            self.log_cb(f"[Auth] Sending HMAC-SHA3-512:        {to_hex(mac)}")
            send_msg(sock, {"type": "AUTH_HMAC", "hmac_hex": to_hex(mac)})

            res = recv_msg(sock)
            if res.get("type") != "AUTH_RESULT":
                self.log_cb(f"[Auth] Unexpected result message: {res}")
                sock.close()
                return "network_error"

            ct = from_hex(res["ciphertext_hex"])
            sig = from_hex(res["signature_hex"])
            self.log_cb(f"[Auth] Result ciphertext: {short_hex(ct)}")
            self.log_cb(f"[Auth] Result signature:  {short_hex(sig)}")

            if not rsa_verify(self.server_sign_pub, ct, sig):
                self.log_cb("[Auth] SIGNATURE INVALID on AUTH_RESULT. Discarding.")
                sock.close()
                return "auth_failed"
            self.log_cb("[Auth] Signature on result verified OK.")

            ack_key, ack_iv = derive_aes_key_iv_from_hash(h_rev_pw)
            self.log_cb(f"[Auth] AES key for ack decryption: {to_hex(ack_key)}")
            self.log_cb(f"[Auth] IV  for ack decryption:    {to_hex(ack_iv)}")

            try:
                pt = aes_decrypt(ack_key, ack_iv, ct)
            except ValueError:
                self.log_cb("[Auth] AES decryption failed (likely wrong password).")
                sock.close()
                return "wrong_password"

            self.log_cb(f"[Auth] Decrypted plaintext (first 64 bytes hex): {to_hex(pt[:64])}")

            if pt.startswith(AUTH_OK_TEXT):
                tail = pt[len(AUTH_OK_TEXT):]
                fixed_len = AES_KEY_LEN + AES_BLOCK_SIZE + HMAC_KEY_LEN
                if len(tail) < fixed_len:
                    self.log_cb(f"[Auth] Unexpected tail length: {len(tail)} bytes.")
                    sock.close()
                    return "auth_failed"

                aes_key = tail[: AES_KEY_LEN]
                iv = tail[AES_KEY_LEN: AES_KEY_LEN + AES_BLOCK_SIZE]
                hmac_key_ch = tail[AES_KEY_LEN + AES_BLOCK_SIZE: fixed_len]
                channel_bytes = tail[fixed_len:]
                try:
                    channel_name = channel_bytes.decode("utf-8")
                except UnicodeDecodeError:
                    channel_name = ""

                self.session_aes_key = aes_key
                self.session_iv = iv
                self.session_hmac_key = hmac_key_ch
                self.username = username
                self.channel = channel_name if channel_name in CHANNELS else None

                self.log_cb("[Auth] Authentication Successful.")
                self.log_cb(f"[Auth] Channel:          {channel_name}")
                self.log_cb(f"[Auth] Channel AES key:  {to_hex(aes_key)}")
                self.log_cb(f"[Auth] Channel IV:       {to_hex(iv)}")
                self.log_cb(f"[Auth] Channel HMAC key: {to_hex(hmac_key_ch)}")

                sock.settimeout(None)
                self.sock = sock
                self._connected = True
                self._recv_thread = threading.Thread(target=self._receive_loop, daemon=True)
                self._recv_thread.start()
                return "ok"

            if pt == AUTH_FAIL_TEXT:
                self.log_cb("[Auth] Server reported: Authentication Unsuccessful.")
                sock.close()
                return "auth_failed"

            if pt == AUTH_CHANNEL_UNAVAILABLE:
                self.log_cb("[Auth] Server reported: Channel Unavailable.")
                sock.close()
                return "channel_unavailable"

            self.log_cb(f"[Auth] Unexpected plaintext: {pt!r}")
            sock.close()
            return "auth_failed"

        except (ConnectionError, OSError, ValueError) as e:
            self.log_cb(f"[Auth] Network error: {e}")
            try: sock.close()
            except OSError: pass
            return "network_error"

    def set_channel(self, channel: str):
        """gui calls this after login to set which channel we're on."""
        self.channel = channel

    def send_broadcast(self, message: str) -> bool:
        if not self._connected or self.session_aes_key is None:
            self.log_cb("Cannot send: not authenticated.")
            return False
        try:
            ct = aes_encrypt(self.session_aes_key, self.session_iv, message.encode("utf-8"))
            mac = hmac_sha3_512(self.session_hmac_key, ct)
            self.log_cb(f"[Send] AES-CBC ciphertext: {short_hex(ct)}")
            self.log_cb(f"[Send] HMAC:               {short_hex(mac)}")
            send_msg(
                self.sock,
                {
                    "type": "BROADCAST",
                    "ciphertext_hex": to_hex(ct),
                    "hmac_hex": to_hex(mac),
                },
            )
            return True
        except (OSError, ConnectionError) as e:
            self.log_cb(f"[Send] Network error: {e}")
            self._mark_disconnected()
            return False

    def _receive_loop(self) -> None:
        while self._connected:
            try:
                msg = recv_msg(self.sock)
            except (ConnectionError, OSError, ValueError):
                self._mark_disconnected()
                return
            if msg.get("type") != "BROADCAST":
                self.log_cb(f"[Recv] Unexpected type: {msg.get('type')}")
                continue

            sender = msg.get("from", "?")
            ct = from_hex(msg.get("ciphertext_hex", ""))
            mac = from_hex(msg.get("hmac_hex", ""))

            self.log_cb(f"[Recv] from '{sender}': ct={short_hex(ct)} hmac={short_hex(mac)}")

            if not hmac_verify(self.session_hmac_key, ct, mac):
                self.log_cb(f"[Recv] HMAC INVALID for message from '{sender}'. Discarded.")
                self.message_cb(sender, "<<INVALID HMAC — message discarded>>")
                continue
            try:
                pt = aes_decrypt(self.session_aes_key, self.session_iv, ct)
            except ValueError:
                self.log_cb(f"[Recv] Decryption failed for message from '{sender}'.")
                self.message_cb(sender, "<<DECRYPTION FAILED — message discarded>>")
                continue

            try:
                text = pt.decode("utf-8")
            except UnicodeDecodeError:
                text = repr(pt)

            self.log_cb(f"[Recv] Plaintext from '{sender}': {text}")
            self.message_cb(sender, text)

    def _mark_disconnected(self):
        if not self._connected:
            return
        self._connected = False
        try:
            if self.sock is not None:
                self.sock.close()
        except OSError:
            pass
        self.sock = None
        self.session_aes_key = None
        self.session_iv = None
        self.session_hmac_key = None
        self.username = None
        self.channel = None
        self.state_cb("DISCONNECTED", {})
        self.log_cb("Disconnected from server.")

    def disconnect(self) -> None:
        if self._connected and self.sock is not None:
            try:
                send_msg(self.sock, {"type": "DISCONNECT"})
            except (OSError, ConnectionError):
                pass
        self._mark_disconnected()


# --- gui ---

# light / sky-blue palette
_C_BG     = "#f0f7ff"
_C_BG2    = "#ffffff"
_C_BG3    = "#dbeafe"
_C_ACCENT = "#0ea5e9"
_C_ACCT2  = "#38bdf8"
_C_DARK   = "#0369a1"
_C_TEXT   = "#0f172a"
_C_DIM    = "#64748b"
_C_GREEN  = "#059669"
_C_WARN   = "#dc2626"
_C_FONT   = ("Segoe UI", 10) if tk.TkVersion else ("TkDefaultFont", 10)
_C_MONO   = ("Consolas", 10) if tk.TkVersion else ("Courier", 10)


def _client_style(root):
    s = ttk.Style(root)
    s.theme_use("clam")
    s.configure(".",
        background=_C_BG, foreground=_C_TEXT,
        troughcolor=_C_BG3, bordercolor=_C_BG3,
        darkcolor=_C_BG3, lightcolor=_C_BG2,
        selectbackground=_C_ACCENT, selectforeground=_C_BG2,
    )
    s.configure("TFrame",       background=_C_BG)
    s.configure("Card.TFrame",  background=_C_BG2)
    s.configure("TLabel",       background=_C_BG,  foreground=_C_TEXT)
    s.configure("Card.TLabel",  background=_C_BG2, foreground=_C_TEXT)
    s.configure("Dim.TLabel",   background=_C_BG2, foreground=_C_DIM)
    s.configure("TLabelframe",
        background=_C_BG2, foreground=_C_DARK,
        bordercolor=_C_BG3, relief="groove",
    )
    s.configure("TLabelframe.Label",
        background=_C_BG2, foreground=_C_DARK,
        font=(_C_FONT[0], 9, "bold"),
    )
    s.configure("TButton",
        background=_C_ACCENT, foreground=_C_BG2,
        borderwidth=0, relief="flat", padding=(10, 5),
        font=(_C_FONT[0], 9, "bold"),
    )
    s.map("TButton",
        background=[("active", _C_DARK), ("disabled", _C_BG3)],
        foreground=[("disabled", _C_DIM)],
    )
    s.configure("TEntry",
        fieldbackground=_C_BG2, foreground=_C_TEXT,
        bordercolor=_C_BG3, insertcolor=_C_TEXT,
    )
    s.configure("TCombobox",
        fieldbackground=_C_BG2, foreground=_C_TEXT,
        selectbackground=_C_ACCENT, selectforeground=_C_BG2,
        arrowcolor=_C_ACCENT, bordercolor=_C_BG3,
    )
    s.map("TCombobox",
        fieldbackground=[("readonly", _C_BG2)],
        selectbackground=[("readonly", _C_ACCENT)],
    )
    s.configure("TNotebook",
        background=_C_BG, bordercolor=_C_BG3, tabmargins=[2, 4, 2, 0],
    )
    s.configure("TNotebook.Tab",
        background=_C_BG3, foreground=_C_DIM,
        padding=[14, 6], borderwidth=0,
        font=(_C_FONT[0], 9, "bold"),
    )
    s.map("TNotebook.Tab",
        background=[("selected", _C_ACCENT)],
        foreground=[("selected", _C_BG2)],
        expand=[("selected", [1, 1, 1, 0])],
    )
    s.configure("Vertical.TScrollbar",
        background=_C_BG3, troughcolor=_C_BG,
        bordercolor=_C_BG, arrowcolor=_C_DIM,
        relief="flat",
    )


class ClientGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("CS432 — Secure Channel CLIENT")
        self.root.geometry("1080x860")
        self.root.configure(bg=_C_BG)
        _client_style(self.root)

        self._gui_q = queue.Queue()
        self.root.after(50, self._poll_gui_queue)

        self._enc_pub_path = tk.StringVar()
        self._sign_pub_path = tk.StringVar()
        self._ip_var = tk.StringVar(value="127.0.0.1")
        self._port_var = tk.StringVar(value="6000")

        self._reg_user = tk.StringVar()
        self._reg_pass = tk.StringVar()
        self._reg_channel = tk.StringVar(value=CHANNELS[0])

        self._login_user = tk.StringVar()
        self._login_pass = tk.StringVar()

        self.core = SecureChannelClient(
            log_cb=self._log_threadsafe,
            state_cb=self._state_threadsafe,
            message_cb=self._msg_threadsafe,
        )

        self._build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_ui(self):
        # ── Header banner ──────────────────────────────────────────────
        banner = tk.Frame(self.root, bg=_C_ACCENT, height=58)
        banner.pack(fill=tk.X)
        banner.pack_propagate(False)
        tk.Label(
            banner, text="  CLIENT",
            bg=_C_ACCENT, fg=_C_BG2,
            font=(_C_FONT[0], 17, "bold"),
        ).pack(side=tk.LEFT, padx=18)
        tk.Label(
            banner, text="CS432 Secure Channel",
            bg=_C_ACCENT, fg=_C_BG,
            font=(_C_FONT[0], 10),
        ).pack(side=tk.LEFT, padx=4)
        self._status_var = tk.StringVar(value="● Not connected")
        self._status_badge = tk.Label(
            banner, textvariable=self._status_var,
            bg=_C_BG2, fg=_C_WARN,
            font=(_C_FONT[0], 9, "bold"),
            padx=10, pady=4,
        )
        self._status_badge.pack(side=tk.RIGHT, padx=18, pady=10)

        body = tk.Frame(self.root, bg=_C_BG)
        body.pack(fill=tk.BOTH, expand=True, padx=10, pady=8)

        # ── Server keys & connection ───────────────────────────────────
        top = ttk.LabelFrame(body, text="SERVER KEYS & CONNECTION")
        top.pack(fill=tk.X, pady=(0, 6))

        ttk.Label(top, text="Enc public key (PEM):", style="Card.TLabel").grid(
            row=0, column=0, sticky="e", padx=(10, 4), pady=5)
        ttk.Entry(top, textvariable=self._enc_pub_path, width=66).grid(
            row=0, column=1, columnspan=2, sticky="we", padx=4)
        ttk.Button(top, text="Browse", command=self._browse_enc_pub, width=8).grid(
            row=0, column=3, padx=(4, 10))

        ttk.Label(top, text="Sign public key (PEM):", style="Card.TLabel").grid(
            row=1, column=0, sticky="e", padx=(10, 4), pady=5)
        ttk.Entry(top, textvariable=self._sign_pub_path, width=66).grid(
            row=1, column=1, columnspan=2, sticky="we", padx=4)
        ttk.Button(top, text="Browse", command=self._browse_sign_pub, width=8).grid(
            row=1, column=3, padx=(4, 10))

        ttk.Label(top, text="Server IP:", style="Card.TLabel").grid(
            row=2, column=0, sticky="e", padx=(10, 4), pady=5)
        ttk.Entry(top, textvariable=self._ip_var, width=22).grid(
            row=2, column=1, sticky="w", padx=4)
        ttk.Label(top, text="Port:", style="Card.TLabel").grid(
            row=2, column=2, sticky="e", padx=4)
        ttk.Entry(top, textvariable=self._port_var, width=8).grid(
            row=2, column=3, sticky="w", padx=(4, 10))

        ttk.Button(top, text="Load Server Keys", command=self._on_load_keys).grid(
            row=3, column=0, columnspan=4, sticky="we", padx=10, pady=(4, 10))
        top.columnconfigure(1, weight=1)

        # ── Enrollment + Login panels side by side ─────────────────────
        actions = tk.Frame(body, bg=_C_BG)
        actions.pack(fill=tk.X, pady=(0, 6))
        actions.columnconfigure(0, weight=1)
        actions.columnconfigure(1, weight=1)

        enr = ttk.LabelFrame(actions, text="ENROLLMENT")
        enr.grid(row=0, column=0, sticky="nswe", padx=(0, 4))
        ttk.Label(enr, text="Username:", style="Card.TLabel").grid(
            row=0, column=0, sticky="e", padx=(10, 4), pady=4)
        ttk.Entry(enr, textvariable=self._reg_user, width=22).grid(
            row=0, column=1, sticky="we", padx=(4, 10))
        ttk.Label(enr, text="Password:", style="Card.TLabel").grid(
            row=1, column=0, sticky="e", padx=(10, 4), pady=4)
        ttk.Entry(enr, textvariable=self._reg_pass, width=22, show="*").grid(
            row=1, column=1, sticky="we", padx=(4, 10))
        ttk.Label(enr, text="Channel:", style="Card.TLabel").grid(
            row=2, column=0, sticky="e", padx=(10, 4), pady=4)
        ttk.Combobox(enr, textvariable=self._reg_channel,
                     values=list(CHANNELS), state="readonly", width=20).grid(
            row=2, column=1, sticky="w", padx=(4, 10))
        ttk.Button(enr, text="Enroll", command=self._on_enroll).grid(
            row=3, column=0, columnspan=2, sticky="we", padx=10, pady=(4, 10))
        enr.columnconfigure(1, weight=1)

        log_f = ttk.LabelFrame(actions, text="LOGIN")
        log_f.grid(row=0, column=1, sticky="nswe", padx=(4, 0))
        ttk.Label(log_f, text="Username:", style="Card.TLabel").grid(
            row=0, column=0, sticky="e", padx=(10, 4), pady=4)
        ttk.Entry(log_f, textvariable=self._login_user, width=22).grid(
            row=0, column=1, sticky="we", padx=(4, 10))
        ttk.Label(log_f, text="Password:", style="Card.TLabel").grid(
            row=1, column=0, sticky="e", padx=(10, 4), pady=4)
        ttk.Entry(log_f, textvariable=self._login_pass, width=22, show="*").grid(
            row=1, column=1, sticky="we", padx=(4, 10))
        btns = tk.Frame(log_f, bg=_C_BG2)
        btns.grid(row=3, column=0, columnspan=2, sticky="we", padx=10, pady=(4, 10))
        self._login_btn = ttk.Button(btns, text="Login", command=self._on_login)
        self._login_btn.pack(side=tk.LEFT, padx=(0, 6))
        self._disconnect_btn = ttk.Button(btns, text="Disconnect",
                                          command=self._on_disconnect, state=tk.DISABLED)
        self._disconnect_btn.pack(side=tk.LEFT)
        log_f.columnconfigure(1, weight=1)

        # ── Notebook: channel chat + crypto log ────────────────────────
        nb = ttk.Notebook(body)
        nb.pack(fill=tk.BOTH, expand=True)

        ch_frame = ttk.Frame(nb)
        ch_header = tk.Frame(ch_frame, bg=_C_BG3, height=36)
        ch_header.pack(fill=tk.X)
        ch_header.pack_propagate(False)
        self._ch_label = tk.Label(
            ch_header, text="Channel: (not authenticated)",
            bg=_C_BG3, fg=_C_DARK,
            font=(_C_FONT[0], 10, "bold"),
        )
        self._ch_label.pack(side=tk.LEFT, padx=10, pady=6)

        msg_box = ttk.Frame(ch_frame, style="Card.TFrame")
        msg_box.pack(fill=tk.BOTH, expand=True, padx=6, pady=(4, 0))
        self._messages_widget = tk.Text(
            msg_box, wrap=tk.WORD, height=16, state=tk.DISABLED,
            bg=_C_BG2, fg=_C_TEXT, relief="flat", borderwidth=0,
            font=_C_FONT, padx=10, pady=8,
        )
        scr = ttk.Scrollbar(msg_box, command=self._messages_widget.yview)
        self._messages_widget.configure(yscrollcommand=scr.set)
        self._messages_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scr.pack(side=tk.RIGHT, fill=tk.Y)

        send_box = tk.Frame(ch_frame, bg=_C_BG3)
        send_box.pack(fill=tk.X, padx=6, pady=4)
        self._compose_var = tk.StringVar()
        self._compose_entry = ttk.Entry(send_box, textvariable=self._compose_var)
        self._compose_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(6, 4), pady=6)
        self._compose_entry.bind("<Return>", lambda _e: self._on_send())
        self._send_btn = ttk.Button(send_box, text="Send ▶", command=self._on_send, state=tk.DISABLED)
        self._send_btn.pack(side=tk.LEFT, padx=(0, 6), pady=6)

        nb.add(ch_frame, text="  Channel  ")

        log_frame = ttk.Frame(nb)
        self._log_widget = tk.Text(
            log_frame, wrap=tk.WORD, height=16,
            bg=_C_BG2, fg=_C_DIM, relief="flat", borderwidth=0,
            font=_C_MONO, padx=8, pady=6,
        )
        scrl = ttk.Scrollbar(log_frame, command=self._log_widget.yview)
        self._log_widget.configure(yscrollcommand=scrl.set)
        self._log_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrl.pack(side=tk.RIGHT, fill=tk.Y)
        nb.add(log_frame, text="  Crypto Log  ")

    def _browse_enc_pub(self):
        p = filedialog.askopenfilename(
            title="Select server enc PUBLIC key (PEM)",
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")],
        )
        if p: self._enc_pub_path.set(p)

    def _browse_sign_pub(self):
        p = filedialog.askopenfilename(
            title="Select server sign PUBLIC key (PEM)",
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")],
        )
        if p: self._sign_pub_path.set(p)

    def _on_load_keys(self):
        if not self._enc_pub_path.get() or not self._sign_pub_path.get():
            messagebox.showerror("Missing keys", "Please choose both server public key files.")
            return
        try:
            self.core.load_server_pubkeys(self._enc_pub_path.get(), self._sign_pub_path.get())
            self._log_threadsafe("Server public keys loaded.")
        except (ValueError, OSError) as e:
            messagebox.showerror("Key load failed", str(e))

    def _validate_address(self):
        ip = self._ip_var.get().strip()
        try:
            port = int(self._port_var.get())
            if not (1 <= port <= 65535):
                raise ValueError
        except ValueError:
            messagebox.showerror("Bad address", "Please enter a valid IP and port (1-65535).")
            return None
        return ip, port

    def _on_enroll(self):
        addr = self._validate_address()
        if addr is None: return
        ip, port = addr

        if self.core.server_enc_pub is None:
            messagebox.showerror("Keys not loaded", "Click 'Load server keys' first.")
            return

        username = self._reg_user.get().strip()
        password = self._reg_pass.get()
        channel = self._reg_channel.get()

        if not username or not password:
            messagebox.showerror("Missing", "Username and password are required.")
            return
        if channel not in CHANNELS:
            messagebox.showerror("Bad channel", "Channel must be IF100 / MATH101 / SPS101.")
            return

        def worker():
            ok = self.core.enroll(ip, port, username, password, channel)
            if ok:
                self._gui_q.put(("info", "Enrollment success", f"User '{username}' enrolled on {channel}."))
            else:
                self._gui_q.put(("error", "Enrollment failed", "See the log for details."))
            self._gui_q.put(("clear_reg_pass", None, None))

        threading.Thread(target=worker, daemon=True).start()

    def _on_login(self):
        addr = self._validate_address()
        if addr is None: return
        ip, port = addr

        if self.core.server_sign_pub is None:
            messagebox.showerror("Keys not loaded", "Click 'Load server keys' first.")
            return

        username = self._login_user.get().strip()
        password = self._login_pass.get()
        if not username or not password:
            messagebox.showerror("Missing", "Username and password are required.")
            return

        self._login_btn.configure(state=tk.DISABLED)
        self._set_status(f"● Authenticating as '{username}'...", _C_ACCENT)

        def worker():
            result = self.core.login(ip, port, username, password)
            self._gui_q.put(("login_result", result, username))
            self._gui_q.put(("clear_login_pass", None, None))

        threading.Thread(target=worker, daemon=True).start()

    def _on_disconnect(self):
        self.core.disconnect()

    def _on_send(self):
        text = self._compose_var.get()
        if not text:
            return
        if self.core.send_broadcast(text):
            self._compose_var.set("")

    def _on_close(self):
        try:
            self.core.disconnect()
        except Exception:
            pass
        self.root.destroy()

    def _log_threadsafe(self, message: str):
        self._gui_q.put(("log", message, None))

    def _state_threadsafe(self, state: str, info: dict):
        self._gui_q.put(("state", state, info))

    def _msg_threadsafe(self, sender: str, text: str):
        self._gui_q.put(("msg", sender, text))

    def _poll_gui_queue(self):
        try:
            while True:
                kind, a, b = self._gui_q.get_nowait()
                if kind == "log":
                    self._append_log(a)
                elif kind == "msg":
                    self._append_message(a, b)
                elif kind == "state":
                    self._handle_state(a, b)
                elif kind == "info":
                    messagebox.showinfo(a, b)
                elif kind == "error":
                    messagebox.showerror(a, b)
                elif kind == "login_result":
                    self._handle_login_result(a, b)
                elif kind == "clear_reg_pass":
                    self._reg_pass.set("")
                elif kind == "clear_login_pass":
                    self._login_pass.set("")
        except queue.Empty:
            pass
        self.root.after(50, self._poll_gui_queue)

    def _append_log(self, text: str):
        self._log_widget.insert(tk.END, text + "\n")
        self._log_widget.see(tk.END)

    def _append_message(self, sender: str, text: str):
        self._messages_widget.configure(state=tk.NORMAL)
        self._messages_widget.insert(tk.END, f"[{sender}] {text}\n")
        self._messages_widget.see(tk.END)
        self._messages_widget.configure(state=tk.DISABLED)

    def _handle_state(self, state: str, _info: dict):
        if state == "DISCONNECTED":
            self._set_status("● Not connected", _C_WARN)
            self._send_btn.configure(state=tk.DISABLED)
            self._login_btn.configure(state=tk.NORMAL)
            self._disconnect_btn.configure(state=tk.DISABLED)
            self._ch_label.configure(text="Channel: (not authenticated)")

    def _handle_login_result(self, result: str, username: str):
        if result == "ok":
            channel = self.core.channel
            self._login_user.set(username)
            self._send_btn.configure(state=tk.NORMAL)
            self._disconnect_btn.configure(state=tk.NORMAL)
            self._login_btn.configure(state=tk.DISABLED)
            ch_text = channel if channel else "(authenticated)"
            self._ch_label.configure(text=f"Channel: {ch_text}")
            self._set_status(f"● Connected as '{username}'  [{ch_text}]", _C_GREEN)
        elif result == "wrong_password":
            messagebox.showerror("Wrong password", "Decryption failed; the password is likely wrong.")
            self._set_status("● Not connected", _C_WARN)
            self._login_btn.configure(state=tk.NORMAL)
        elif result == "auth_failed":
            messagebox.showerror("Authentication failed", "Server rejected the login.")
            self._set_status("● Not connected", _C_WARN)
            self._login_btn.configure(state=tk.NORMAL)
        elif result == "channel_unavailable":
            messagebox.showwarning("Channel unavailable", "The channel keys have not been generated on the server yet.")
            self._set_status("● Not connected", _C_WARN)
            self._login_btn.configure(state=tk.NORMAL)
        else:
            messagebox.showerror("Network error", "Could not reach server. See log.")
            self._set_status("● Not connected", _C_WARN)
            self._login_btn.configure(state=tk.NORMAL)

    def _set_status(self, s: str, color: str = _C_WARN):
        self._status_var.set(s)
        self._status_badge.configure(fg=color)

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    ClientGUI().run()
