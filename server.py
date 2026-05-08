# server 
# mehmet emre tekesin -- bilgekagan durmaz

import json
import os
import queue
import socket
import struct
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA3_512, HMAC as CryptoHMAC
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import pad, unpad


CHANNELS    = ("IF100", "MATH101", "SPS101")
BLOCK_SIZE  = 16
SYMKEY_LEN  = 32
NONCE_BYTES = 16   # 128-bit challenge

AUTH_SUCCESS = b"Authentication Successful"
AUTH_FAILURE = b"Authentication Unsuccessful"
CHAN_UNAVAIL  = b"Channel Unavailable"

ENROLL_DB = "server_enrollments.json"

# gui colors - dark blue-grey
C_BG    = "#1a1f2e"
C_PANEL = "#242938"
C_DEEP  = "#2d3349"
C_ACC   = "#4fa3e0"
C_LITE  = "#7ec8f5"
C_FG    = "#e6edf7"
C_MUTED = "#7b8db0"
C_OK    = "#3dba8c"
C_ERR   = "#e05c5c"
FONT = ("Lucida Console", 9)
MONO = ("Lucida Console", 9)


# socket wrapper that buffers reads so partial TCP messages dont break json parsing
class Connection:
    def __init__(self, sock):
        self._sock = sock
        self._rbuf = b""

    def recv(self):
        # keep reading until we have the 4 byte header
        while len(self._rbuf) < 4:
            chunk = self._sock.recv(4096)
            if not chunk:
                raise ConnectionError("peer disconnected")
            self._rbuf += chunk

        mlen = struct.unpack(">I", self._rbuf[:4])[0]
        if mlen == 0 or mlen > 16 * 1024 * 1024:
            raise ValueError(f"frame length {mlen} out of range")
        self._rbuf = self._rbuf[4:]

        while len(self._rbuf) < mlen:
            chunk = self._sock.recv(4096)
            if not chunk:
                raise ConnectionError("dropped mid message")
            self._rbuf += chunk

        data = self._rbuf[:mlen]
        self._rbuf = self._rbuf[mlen:]
        return json.loads(data.decode("utf-8"))

    def send(self, obj):
        raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        self._sock.sendall(struct.pack(">I", len(raw)) + raw)

    def close(self):
        try:
            self._sock.shutdown(socket.SHUT_RDWR)
        except:
            pass
        try:
            self._sock.close()
        except:
            pass


# main server class -- all crypto helpers are static methods inside so
# module level stays clean
class ChannelServer:

    # crypto helpers -- static so they dont need self, just grouped here

    @staticmethod
    def _sha3(data: bytes) -> bytes:
        h = SHA3_512.new()
        h.update(data)
        return h.digest()

    @staticmethod
    def _aes_enc(key, iv, pt):
        return AES.new(key, AES.MODE_CBC, iv).encrypt(pad(pt, BLOCK_SIZE))

    @staticmethod
    def _aes_dec(key, iv, ct):
        return unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), BLOCK_SIZE)

    @staticmethod
    def _hmac(key, data):
        mac = CryptoHMAC.new(key, digestmod=SHA3_512)
        mac.update(data)
        return mac.digest()

    @staticmethod
    def _hmac_ok(key, data, tag):
        # timing safe -- verify() raises on mismatch rather than returning false
        try:
            mac = CryptoHMAC.new(key, digestmod=SHA3_512)
            mac.update(data)
            mac.verify(tag)
            return True
        except:
            return False

    @staticmethod
    def _load_pem(path):
        return RSA.import_key(open(path, "rb").read())

    @staticmethod
    def _oaep_dec(priv, ct):
        return PKCS1_OAEP.new(priv, hashAlgo=SHA3_512).decrypt(ct)

    @staticmethod
    def _sign(priv, data):
        return pkcs1_15.new(priv).sign(SHA3_512.new(data))

    @staticmethod
    def _kiv(h64: bytes):
        # first 32 = key, next 16 = iv, last 16 unused
        return h64[:SYMKEY_LEN], h64[SYMKEY_LEN : SYMKEY_LEN + BLOCK_SIZE]

    @staticmethod
    def _h(b):
        return b.hex().upper()

    @staticmethod
    def _u(s):
        return bytes.fromhex(s)

    @staticmethod
    def _fmt(b, w=12):
        # abbreviated hex for log output, keeps lines readable
        s = b.hex().upper()
        if len(b) <= w * 2:
            return s
        return f"{s[:w*2]}…{s[-8:]} ({len(b)}B)"

    @staticmethod
    def _parse_enroll(raw: bytes):
        # format: [64B H(pw)] [64B H(rpw)] [1B ulen] [username] [1B clen] [channel]
        # hashes go first so the payload fits under RSA-3072 OAEP limit (~254B)
        if len(raw) < 64 + 64 + 3:
            raise ValueError("payload too short to be valid")
        pos = 0
        h_pw  = raw[pos : pos+64];  pos += 64
        h_rpw = raw[pos : pos+64];  pos += 64

        ulen = raw[pos];  pos += 1
        if not (1 <= ulen <= 32) or pos + ulen > len(raw):
            raise ValueError(f"username length {ulen} is out of range")
        uname = raw[pos : pos+ulen].decode("utf-8");  pos += ulen

        clen = raw[pos];  pos += 1
        if not (1 <= clen <= 16) or pos + clen != len(raw):
            raise ValueError(f"channel length {clen} doesn't add up")
        chan = raw[pos : pos+clen].decode("utf-8")

        return uname, h_pw, h_rpw, chan

    def __init__(self, log_fn, ev_fn):
        self._log = log_fn   # log_fn(tab, msg)
        self._ev  = ev_fn    # ev_fn(event, data)

        self._enc_key = None
        self._sig_key = None
        self._lsock   = None
        self._running = False

        # db: username -> pw hash, rpw hash, channel
        self._db_mu = threading.Lock()
        self._db    = self._load_db()

        # channel -> (aes key, iv, hmac key) as tuples so nothing changes after being set
        self._key_mu = threading.Lock()
        self._ckeys  = {}

        # online users: username -> (conn, channel, addr)
        self._sess_mu  = threading.Lock()
        self._sessions = {}

    # --- public interface ---

    def load_keypair(self, enc_path, sig_path):
        self._enc_key = self._load_pem(enc_path)
        self._sig_key = self._load_pem(sig_path)

        nb = 384   # RSA-3072 = 384 bytes
        self._log("server", f"enc/dec key loaded from: {enc_path}")
        self._log("server", f"  n = {self._h(self._enc_key.n.to_bytes(nb, 'big'))}")
        ebytes = (self._enc_key.e.bit_length() + 7) // 8
        self._log("server", f"  e = {self._h(self._enc_key.e.to_bytes(ebytes, 'big'))}")
        self._log("server", f"  d = {self._fmt(self._enc_key.d.to_bytes(nb, 'big'))}")

        self._log("server", f"sign key loaded from: {sig_path}")
        self._log("server", f"  n = {self._h(self._sig_key.n.to_bytes(nb, 'big'))}")
        ebytes2 = (self._sig_key.e.bit_length() + 7) // 8
        self._log("server", f"  e = {self._h(self._sig_key.e.to_bytes(ebytes2, 'big'))}")
        self._log("server", f"  d = {self._fmt(self._sig_key.d.to_bytes(nb, 'big'))}")

    def set_channel_keys(self, channel, master):
        if channel not in CHANNELS:
            raise ValueError(f"'{channel}' is not a valid channel")

        with self._key_mu:
            if channel in self._ckeys:
                self._log("server", f"[{channel}] keys already set, not regenerating")
                return

            # aes key+iv from sha3(master)
            h_fwd = self._sha3(master.encode())
            aes_k, iv = self._kiv(h_fwd)

            # hmac key from sha3(reversed master) to keep it independent from enc key
            h_rev  = self._sha3(master[::-1].encode())
            hmac_k = h_rev[:SYMKEY_LEN]

            self._ckeys[channel] = (aes_k, iv, hmac_k)

        self._log(channel, f"master secret hash = {self._h(h_fwd)}")
        self._log(channel, f"AES key  = {self._h(aes_k)}")
        self._log(channel, f"IV       = {self._h(iv)}")
        self._log(channel, f"HMAC key = {self._h(hmac_k)}")
        self._ev("keys_set", channel)

    def listen(self, port):
        if not self._enc_key or not self._sig_key:
            raise RuntimeError("call load_keypair() before listen()")
        if self._running:
            return
        self._lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._lsock.bind(("0.0.0.0", port))
        self._lsock.listen(8)
        self._running = True
        threading.Thread(target=self._acceptor, daemon=True).start()
        self._log("server", f"server is up on port {port}")

    def shutdown(self):
        if not self._running:
            return
        self._running = False
        try:   self._lsock.shutdown(socket.SHUT_RDWR)
        except: pass
        try:   self._lsock.close()
        except: pass

        with self._sess_mu:
            for uname, (conn, _, _) in list(self._sessions.items()):
                conn.close()
            self._sessions.clear()

        self._ev("sessions_changed", None)
        self._log("server", "server stopped")

    def online_list(self):
        with self._sess_mu:
            return [(u, ch, addr) for u, (_, ch, addr) in self._sessions.items()]

    def enrolled_list(self):
        with self._db_mu:
            return [(u, r["ch"]) for u, r in self._db.items()]

    # server doesnt decrypt, just forwards ciphertext to everyone in the channel

    def _fanout(self, channel, sender, ct_h, mac_h):
        pkt = {
            "type": "MSG",
            "sender": sender,
            "ch": channel,
            "ct_hex": ct_h,
            "mac_hex": mac_h
        }
        with self._sess_mu:
            targets = [(u, c) for u, (c, ch, _) in self._sessions.items()
                       if ch == channel]
        sent = 0
        for _, conn in targets:
            try:
                conn.send(pkt)
                sent += 1
            except:
                pass
        self._log(channel, f"-> relayed from '{sender}' to {sent} client(s)")

    def _broadcast_loop(self, conn, username, channel):
        # just relay messages, server doesnt look at the content
        while True:
            try:
                msg = conn.recv()
            except:
                return

            kind = msg.get("type")
            if kind == "MSG":
                ct_h  = msg.get("ct_hex", "")
                mac_h = msg.get("mac_hex", "")
                if ct_h:
                    self._log(channel, f"<- '{username}': {self._fmt(bytes.fromhex(ct_h))}")
                self._fanout(channel, username, ct_h, mac_h)
            elif kind == "BYE":
                self._log("server", f"'{username}' disconnected")
                return
            else:
                self._log("server", f"got unknown msg type '{kind}' from '{username}'")

    # challenge-response auth using HMAC-SHA3-512

    def _authenticate(self, conn, msg, addr):
        uname = msg.get("user", "").strip()
        self._log("server", f"[auth] login attempt: '{uname}' from {addr[0]}:{addr[1]}")

        with self._db_mu:
            rec = self._db.get(uname)

        if rec is None:
            self._log("server", f"[auth] '{uname}' not in DB -- challenging anyway to avoid leaking valid usernames")

        # check if already logged in before sending the challenge
        with self._sess_mu:
            already_on = uname in self._sessions

        # always send a challenge even for unknown users -- prevents username enumeration
        nonce = get_random_bytes(NONCE_BYTES)
        self._log("server", f"[auth] challenge (128-bit random) = {self._h(nonce)}")
        conn.send({"type": "CHALLENGE", "nonce_hex": self._h(nonce)})

        reply = conn.recv()
        if reply.get("type") != "HMAC_RESP":
            self._log("server", f"[auth] expected HMAC_RESP but got '{reply.get('type')}'")
            return None

        client_mac = reply.get("mac_hex", "")
        self._log("server", f"[auth] received HMAC from client: {client_mac}")

        # compute ack keys now regardless of outcome
        # so success and failure produce identical looking wire messages
        if rec:
            try:
                h_pw  = bytes.fromhex(rec["pw"])
                h_rpw = bytes.fromhex(rec["rpw"])
            except (KeyError, ValueError) as e:
                self._log("server", f"[auth] DB entry for '{uname}' is corrupted: {e}")
                rec = None  # treat as unknown

        if rec:
            hmac_key     = h_pw[SYMKEY_LEN:]               # lower half of H(pw) = bytes 32-63
            ack_k        = h_rpw[SYMKEY_LEN:]               # lower half of H(rpw) = AES-256 key
            ack_v        = h_rpw[BLOCK_SIZE:SYMKEY_LEN]     # 2nd quarter of H(rpw) = IV (bytes 16-31)
            expected_mac = self._hmac(hmac_key, nonce)
            self._log("server", f"[auth] expected HMAC = {self._h(expected_mac)}")
            try:
                auth_ok = self._hmac_ok(hmac_key, nonce, bytes.fromhex(client_mac))
            except:
                auth_ok = False
        else:
            # unknown user -- random keys so we still return a valid looking ciphertext
            ack_k   = get_random_bytes(SYMKEY_LEN)
            ack_v   = get_random_bytes(BLOCK_SIZE)
            auth_ok = False

        # closure so ack keys dont need to be passed into every branch
        def send_result(plaintext):
            ct  = self._aes_enc(ack_k, ack_v, plaintext)
            sig = self._sign(self._sig_key, ct)
            self._log("server", f"[auth] sending result: ct={self._fmt(ct)}  sig={self._fmt(sig)}")
            conn.send({
                "type":   "LOGIN_RESULT",
                "ct_hex": self._h(ct),
                "sig_hex": self._h(sig)
            })

        if not auth_ok:
            self._log("server", "[auth] HMAC check failed")
            send_result(AUTH_FAILURE)
            return None

        self._log("server", f"[auth] HMAC verified OK for '{uname}'")

        if already_on:
            self._log("server", f"[auth] '{uname}' is already logged in — rejecting")
            send_result(AUTH_FAILURE)
            return None

        channel = rec["ch"]
        with self._key_mu:
            ck = self._ckeys.get(channel)

        if ck is None:
            self._log("server", f"[auth] channel '{channel}' has no keys yet")
            send_result(CHAN_UNAVAIL)
            return None

        # double check under lock in case two logins for the same user raced
        with self._sess_mu:
            if uname in self._sessions:
                self._log("server", f"[auth] '{uname}' just appeared online (race condition), rejecting")
                send_result(AUTH_FAILURE)
                return None
            self._sessions[uname] = (conn, channel, addr)
        self._ev("sessions_changed", None)

        # pack channel keys into success blob
        # AUTH_SUCCESS + 1B(ch len) + ch name + aes key(32) + iv(16) + hmac key(32)
        ch_aes, ch_iv, ch_hmac = ck
        ch_b = channel.encode("utf-8")
        blob = AUTH_SUCCESS + bytes([len(ch_b)]) + ch_b + ch_aes + ch_iv + ch_hmac
        send_result(blob)
        self._log("server", f"[auth] '{uname}' is now authenticated on channel {channel}")
        return uname, channel

    # enrollment

    def _enroll(self, conn, msg, addr):
        ct_hex = msg.get("enc_hex", "")
        if not ct_hex:
            self._enroll_reply(conn, "error: missing payload")
            return

        ct = bytes.fromhex(ct_hex)
        self._log("server", f"[enroll] ciphertext from {addr[0]}: {self._fmt(ct)}")

        try:
            plain = self._oaep_dec(self._enc_key, ct)
        except Exception as ex:
            self._log("server", f"[enroll] RSA decrypt failed: {ex}")
            self._enroll_reply(conn, "error: decryption failed")
            return

        try:
            uname, h_pw, h_rpw, channel = self._parse_enroll(plain)
        except (ValueError, UnicodeDecodeError) as ex:
            self._log("server", f"[enroll] parse failed: {ex}")
            self._enroll_reply(conn, "error: bad payload")
            return

        self._log("server", f"[enroll] user='{uname}'  channel={channel}")
        self._log("server", f"  H(pw)  = {self._h(h_pw)}")
        self._log("server", f"  H(rpw) = {self._h(h_rpw)}")

        if not (1 <= len(uname) <= 32):
            self._enroll_reply(conn, "error: invalid username length")
            return
        if channel not in CHANNELS:
            self._enroll_reply(conn, "error: channel doesn't exist")
            return

        with self._db_mu:
            if uname in self._db:
                self._log("server", f"[enroll] '{uname}' already registered")
                self._enroll_reply(conn, "error: username taken")
                return
            self._db[uname] = {
                "pw":  self._h(h_pw),
                "rpw": self._h(h_rpw),
                "ch":  channel
            }
            self._save_db()

        self._log("server", f"[enroll] registered '{uname}' on {channel}")
        self._enroll_reply(conn, f"success: enrolled '{uname}' on {channel}")

    def _enroll_reply(self, conn, text):
        sig = self._sign(self._sig_key, text.encode("utf-8"))
        self._log("server", f"[enroll] reply = '{text}'")
        self._log("server", f"  sig = {self._fmt(sig)}")
        conn.send({
            "type":    "REG_RESULT",
            "text":    text,
            "sig_hex": self._h(sig)
        })

    # one thread per client, handles whatever they send first

    def _client_session(self, raw_sock, addr):
        conn = Connection(raw_sock)
        username = None
        channel  = None
        try:
            first = conn.recv()
            mt = first.get("type")

            if mt == "REGISTER":
                self._enroll(conn, first, addr)

            elif mt == "LOGIN":
                result = self._authenticate(conn, first, addr)
                if result is not None:
                    username, channel = result
                    self._broadcast_loop(conn, username, channel)
            else:
                self._log("server", f"unexpected message type '{mt}' from {addr[0]}:{addr[1]}")

        except Exception as ex:
            self._log("server", f"error in session with {addr}: {type(ex).__name__}: {ex}")
        finally:
            if username is not None:
                with self._sess_mu:
                    if username in self._sessions and self._sessions[username][0] is conn:
                        del self._sessions[username]
                self._ev("sessions_changed", None)
                self._log("server", f"'{username}' disconnected (was on {channel})")
            conn.close()

    # acceptor loop

    def _acceptor(self):
        while self._running:
            try:
                raw, addr = self._lsock.accept()
            except OSError:
                break
            self._log("server", f"new connection from {addr[0]}:{addr[1]}")
            t = threading.Thread(target=self._client_session, args=(raw, addr), daemon=True)
            t.start()

    # simple json file db

    def _load_db(self):
        if not os.path.exists(ENROLL_DB):
            return {}
        try:
            with open(ENROLL_DB) as f:
                return json.load(f)
        except:
            return {}

    def _save_db(self):
        with open(ENROLL_DB, "w") as f:
            json.dump(self._db, f, indent=2)


# --- GUI ---

def _apply_theme(root):
    s = ttk.Style(root)
    s.theme_use("clam")
    s.configure(".", background=C_BG, foreground=C_FG,
                 troughcolor=C_PANEL, bordercolor=C_DEEP,
                 darkcolor=C_PANEL, lightcolor=C_DEEP,
                 selectbackground=C_ACC, selectforeground=C_FG,
                 font=FONT)
    s.configure("TFrame",   background=C_BG)
    s.configure("P.TFrame", background=C_PANEL)
    s.configure("TLabel",   background=C_BG,    foreground=C_FG,    font=FONT)
    s.configure("P.TLabel", background=C_PANEL, foreground=C_FG,    font=FONT)
    s.configure("M.TLabel", background=C_PANEL, foreground=C_MUTED, font=FONT)
    s.configure("TLabelframe",
                background=C_PANEL, foreground=C_ACC,
                bordercolor=C_DEEP, relief="groove")
    s.configure("TLabelframe.Label",
                background=C_PANEL, foreground=C_ACC,
                font=(FONT[0], FONT[1], "bold"))
    s.configure("TButton",
                background=C_ACC, foreground=C_BG,
                borderwidth=0, relief="flat", padding=(10, 5),
                font=(FONT[0], FONT[1], "bold"))
    s.map("TButton",
          background=[("active", C_LITE), ("disabled", C_DEEP)],
          foreground=[("active",  C_BG),  ("disabled", C_MUTED)])
    s.configure("TEntry",
                fieldbackground=C_DEEP, foreground=C_FG,
                bordercolor=C_DEEP, insertcolor=C_FG, font=FONT)
    s.configure("TCombobox",
                fieldbackground=C_DEEP, foreground=C_FG,
                selectbackground=C_ACC, arrowcolor=C_FG,
                bordercolor=C_DEEP, font=FONT)
    s.map("TCombobox", fieldbackground=[("readonly", C_DEEP)])
    s.configure("TNotebook", background=C_BG, bordercolor=C_DEEP, tabmargins=[2, 4, 2, 0])
    s.configure("TNotebook.Tab",
                background=C_DEEP, foreground=C_MUTED,
                padding=[14, 6], font=(FONT[0], FONT[1], "bold"))
    s.map("TNotebook.Tab",
          background=[("selected", C_ACC)],
          foreground=[("selected", C_BG)],
          expand=[("selected", [1, 1, 1, 0])])
    s.configure("Vertical.TScrollbar",
                background=C_DEEP, troughcolor=C_PANEL,
                bordercolor=C_PANEL, arrowcolor=C_MUTED, relief="flat")


class ServerGUI:

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("CS432 — SERVER")
        self.root.geometry("1140x860")
        self.root.configure(bg=C_BG)
        _apply_theme(self.root)

        self._q = queue.Queue()
        self.root.after(40, self._drain)

        self._logs = {}  # tab name -> Text widget

        self.srv = ChannelServer(
            log_fn=lambda tab, msg: self._q.put(("log", tab, msg)),
            ev_fn= lambda name, d:  self._q.put(("ev",  name, d)),
        )

        self._v_enc  = tk.StringVar()
        self._v_sig  = tk.StringVar()
        self._v_port = tk.StringVar(value="6000")
        self._v_sec  = {ch: tk.StringVar() for ch in CHANNELS}
        self._v_chst = {ch: tk.StringVar(value="—") for ch in CHANNELS}

        self._build()
        self.root.protocol("WM_DELETE_WINDOW", self._quit)

    def _build(self):
        # top banner
        banner = tk.Frame(self.root, bg=C_ACC, height=54)
        banner.pack(fill=tk.X)
        banner.pack_propagate(False)
        tk.Label(banner, text="  SERVER  ", bg=C_ACC, fg=C_BG,
                 font=(FONT[0], 16, "bold")).pack(side=tk.LEFT, padx=16)
        tk.Label(banner, text="CS432 Secure Channel", bg=C_ACC, fg=C_PANEL,
                 font=FONT).pack(side=tk.LEFT, padx=2)
        self._badge = tk.Label(banner, text="● OFFLINE", bg=C_PANEL, fg=C_ERR,
                                font=(FONT[0], FONT[1], "bold"), padx=10, pady=4)
        self._badge.pack(side=tk.RIGHT, padx=14, pady=10)

        body = tk.Frame(self.root, bg=C_BG)
        body.pack(fill=tk.BOTH, expand=True, padx=10, pady=8)

        # left panel
        left = tk.Frame(body, bg=C_BG)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 8))

        sf = ttk.LabelFrame(left, text="SERVER SETUP")
        sf.pack(fill=tk.X, pady=(0, 6))

        def lrow(parent, label, var, r, btn_cmd=None, show=None):
            ttk.Label(parent, text=label, style="P.TLabel").grid(
                row=r, column=0, sticky="e", padx=(8, 4), pady=3)
            kw = {"show": show} if show else {}
            ttk.Entry(parent, textvariable=var, width=30, **kw).grid(
                row=r, column=1, sticky="we", padx=4)
            if btn_cmd:
                ttk.Button(parent, text="…", command=btn_cmd, width=3).grid(
                    row=r, column=2, padx=(0, 6))

        lrow(sf, "Port:",     self._v_port, 0)
        lrow(sf, "Enc key:",  self._v_enc,  1, btn_cmd=self._pick_enc)
        lrow(sf, "Sign key:", self._v_sig,  2, btn_cmd=self._pick_sig)
        sf.columnconfigure(1, weight=1)

        btns = tk.Frame(sf, bg=C_PANEL)
        btns.grid(row=3, column=0, columnspan=3, sticky="we", padx=8, pady=(4, 8))
        self._btn_start = ttk.Button(btns, text="▶ Start", command=self._start)
        self._btn_start.pack(side=tk.LEFT, padx=(0, 6))
        self._btn_stop = ttk.Button(btns, text="■ Stop", command=self._stop, state=tk.DISABLED)
        self._btn_stop.pack(side=tk.LEFT)

        ckf = ttk.LabelFrame(left, text="CHANNEL MASTER SECRETS")
        ckf.pack(fill=tk.X, pady=(0, 6))
        for i, ch in enumerate(CHANNELS):
            ttk.Label(ckf, text=ch, style="P.TLabel",
                      font=(FONT[0], FONT[1], "bold"), width=9).grid(
                row=i, column=0, sticky="e", padx=(8, 4), pady=3)
            ttk.Entry(ckf, textvariable=self._v_sec[ch], width=20, show="*").grid(
                row=i, column=1, sticky="we", padx=4)
            ttk.Button(ckf, text="Set", width=5,
                       command=lambda c=ch: self._gen_keys(c)).grid(
                row=i, column=2, padx=4)
            ttk.Label(ckf, textvariable=self._v_chst[ch], style="M.TLabel",
                      width=8).grid(row=i, column=3, sticky="w", padx=(2, 6))
        ckf.columnconfigure(1, weight=1)

        uf = ttk.LabelFrame(left, text="CONNECTED USERS")
        uf.pack(fill=tk.X)
        self._ul = tk.Listbox(uf, height=4, bg=C_DEEP, fg=C_OK,
                               selectbackground=C_ACC, relief="flat",
                               borderwidth=0, font=MONO)
        self._ul.pack(fill=tk.X, padx=6, pady=6)

        # log tabs on the right
        nb = ttk.Notebook(body)
        nb.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        for ch in CHANNELS:
            f = ttk.Frame(nb)
            t = tk.Text(f, wrap=tk.WORD, bg=C_DEEP, fg=C_OK,
                        insertbackground=C_FG, relief="flat",
                        borderwidth=0, font=MONO, padx=6, pady=4)
            sc = ttk.Scrollbar(f, command=t.yview)
            t.configure(yscrollcommand=sc.set)
            t.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            sc.pack(side=tk.RIGHT, fill=tk.Y)
            nb.add(f, text=f"  {ch}  ")
            self._logs[ch] = t

        # main server log (not channel specific)
        fs = ttk.Frame(nb)
        ts = tk.Text(fs, wrap=tk.WORD, bg=C_DEEP, fg=C_LITE,
                     insertbackground=C_FG, relief="flat",
                     borderwidth=0, font=MONO, padx=6, pady=4)
        ss = ttk.Scrollbar(fs, command=ts.yview)
        ts.configure(yscrollcommand=ss.set)
        ts.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        ss.pack(side=tk.RIGHT, fill=tk.Y)
        nb.add(fs, text="  Server Log  ")
        self._logs["server"] = ts

    def _pick_enc(self):
        p = filedialog.askopenfilename(title="Select enc/dec key (PEM)",
                                       filetypes=[("PEM", "*.pem"), ("All", "*.*")])
        if p:
            self._v_enc.set(p)

    def _pick_sig(self):
        p = filedialog.askopenfilename(title="Select sign key (PEM)",
                                       filetypes=[("PEM", "*.pem"), ("All", "*.*")])
        if p:
            self._v_sig.set(p)

    def _start(self):
        try:
            port = int(self._v_port.get())
            if not 1 <= port <= 65535:
                raise ValueError
        except ValueError:
            messagebox.showerror("Bad port", "Port must be a number between 1 and 65535.")
            return
        if not self._v_enc.get() or not self._v_sig.get():
            messagebox.showerror("Missing keys", "Please select both PEM files first.")
            return
        try:
            self.srv.load_keypair(self._v_enc.get(), self._v_sig.get())
            self.srv.listen(port)
        except Exception as ex:
            messagebox.showerror("Failed to start", str(ex))
            return
        self._btn_start.configure(state=tk.DISABLED)
        self._btn_stop.configure(state=tk.NORMAL)
        self._badge.configure(text="● ONLINE", fg=C_OK)

    def _stop(self):
        self.srv.shutdown()
        self._btn_start.configure(state=tk.NORMAL)
        self._btn_stop.configure(state=tk.DISABLED)
        self._badge.configure(text="● OFFLINE", fg=C_ERR)

    def _gen_keys(self, ch):
        secret = self._v_sec[ch].get()
        if not secret:
            messagebox.showerror("No secret", f"Type a master secret for {ch} first.")
            return
        try:
            self.srv.set_channel_keys(ch, secret)
            self._v_chst[ch].set("READY")
        except Exception as ex:
            messagebox.showerror("Error", str(ex))

    def _quit(self):
        try:
            self.srv.shutdown()
        except:
            pass
        self.root.destroy()

    def _drain(self):
        # drain queue then reschedule itself
        try:
            while True:
                item = self._q.get_nowait()
                if item[0] == "log":
                    _, tab, text = item
                    w = self._logs.get(tab, self._logs["server"])
                    w.insert(tk.END, text + "\n")
                    w.see(tk.END)
                elif item[0] == "ev":
                    _, name, _ = item
                    if name == "sessions_changed":
                        self._ul.delete(0, tk.END)
                        for u, ch, addr in self.srv.online_list():
                            self._ul.insert(tk.END, f"{u}  [{ch}]  {addr[0]}")
        except queue.Empty:
            pass
        self.root.after(40, self._drain)

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    ServerGUI().run()
