# client 
# mehmet emre tekesin - bilgekagan durmaz

import json
import queue
import socket
import struct
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA3_512, HMAC as CryptoHMAC
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import pad, unpad


CHANNELS = ("IF100", "MATH101", "SPS101")

#  palette — light blue
C_BG   = "#f0f7ff"
C_CARD = "#ffffff"
C_BAND = "#dbeafe"
C_ACC  = "#0ea5e9"
C_DARK = "#0369a1"
C_INK  = "#0f172a"
C_SUB  = "#64748b"
C_OK   = "#059669"
C_ERR  = "#dc2626"
FONT   = ("Segoe UI", 10)
MONO   = ("Consolas", 10)


def _theme(root):
    s = ttk.Style(root)
    s.theme_use("clam")
    s.configure(".", background=C_BG, foreground=C_INK,
                 troughcolor=C_BAND, bordercolor=C_BAND,
                 darkcolor=C_BAND, lightcolor=C_CARD,
                 selectbackground=C_ACC, selectforeground=C_CARD)
    s.configure("TFrame",        background=C_BG)
    s.configure("Card.TFrame",   background=C_CARD)
    s.configure("TLabel",        background=C_BG,   foreground=C_INK)
    s.configure("Card.TLabel",   background=C_CARD, foreground=C_INK)
    s.configure("TLabelframe",
                background=C_CARD, foreground=C_DARK,
                bordercolor=C_BAND, relief="groove")
    s.configure("TLabelframe.Label",
                background=C_CARD, foreground=C_DARK,
                font=(FONT[0], 9, "bold"))
    s.configure("TButton",
                background=C_ACC, foreground=C_CARD,
                borderwidth=0, relief="flat", padding=(10, 5),
                font=(FONT[0], 9, "bold"))
    s.map("TButton",
          background=[("active", C_DARK), ("disabled", C_BAND)],
          foreground=[("disabled", C_SUB)])
    s.configure("TEntry",
                fieldbackground=C_CARD, foreground=C_INK,
                bordercolor=C_BAND, insertcolor=C_INK)
    s.configure("TCombobox",
                fieldbackground=C_CARD, foreground=C_INK,
                selectbackground=C_ACC, arrowcolor=C_ACC, bordercolor=C_BAND)
    s.map("TCombobox", fieldbackground=[("readonly", C_CARD)])
    s.configure("TNotebook",
                background=C_BG, bordercolor=C_BAND, tabmargins=[2, 4, 2, 0])
    s.configure("TNotebook.Tab",
                background=C_BAND, foreground=C_SUB,
                padding=[14, 6], font=(FONT[0], 9, "bold"))
    s.map("TNotebook.Tab",
          background=[("selected", C_ACC)],
          foreground=[("selected", C_CARD)],
          expand=[("selected", [1, 1, 1, 0])])
    s.configure("Vertical.TScrollbar",
                background=C_BAND, troughcolor=C_BG,
                bordercolor=C_BG, arrowcolor=C_SUB, relief="flat")


# everything in one class -- gui, session, network, crypto
# threads push to self._eq and _tick() drains it every 40ms
class SecureClient:

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("CS432 — CLIENT")
        self.root.geometry("1100x860")
        self.root.configure(bg=C_BG)
        _theme(self.root)

        # session dict when logged in, None when not -- keys: aes iv mac ch user
        self._sess  = None
        self._conn  = None   # socket stays open during broadcast phase
        self._alive = False  # receiver thread running

        # server public keys, must be loaded before enrollment or login
        self._pub_enc = None
        self._pub_sig = None

        # threads push events here, main thread drains with _tick()
        self._eq = queue.Queue()
        self.root.after(40, self._tick)

        # form fields
        self._v_enc   = tk.StringVar()
        self._v_sig   = tk.StringVar()
        self._v_ip    = tk.StringVar(value="127.0.0.1")
        self._v_port  = tk.StringVar(value="6000")
        self._v_ruser = tk.StringVar()
        self._v_rpass = tk.StringVar()
        self._v_rchan = tk.StringVar(value=CHANNELS[0])
        self._v_luser = tk.StringVar()
        self._v_lpass = tk.StringVar()
        self._v_stat  = tk.StringVar(value="● Not connected")
        self._v_chanl = tk.StringVar(value="—")

        self._build()
        self.root.protocol("WM_DELETE_WINDOW", self._quit)

    # 4 byte big-endian length prefix then JSON -- must match server framing

    def _readall(self, sock, n):
        # blocking read of exactly n bytes
        buf = b""
        while len(buf) < n:
            got = sock.recv(n - len(buf))
            if not got:
                raise ConnectionError("server closed the connection")
            buf += got
        return buf

    def _net_recv(self, sock):
        size = struct.unpack(">I", self._readall(sock, 4))[0]
        if size == 0 or size > 16 * 1024 * 1024:
            raise ValueError(f"frame size {size} out of range")
        return json.loads(self._readall(sock, size).decode("utf-8"))

    def _net_send(self, sock, data):
        raw = json.dumps(data, separators=(",", ":")).encode("utf-8")
        sock.sendall(struct.pack(">I", len(raw)) + raw)

    # runs on main thread so it can write directly to the log widget

    def _load_keys(self, enc_path, sig_path):
        self._pub_enc = RSA.import_key(open(enc_path, "rb").read())
        self._pub_sig = RSA.import_key(open(sig_path, "rb").read())

        for label, k, path in (("enc", self._pub_enc, enc_path),
                                ("sig", self._pub_sig, sig_path)):
            if k.has_private():
                raise ValueError(
                    f"{label} key at '{path}' is a private key — "
                    "only the server's PUBLIC key should be loaded here."
                )
            self._write_log(f"{label} public key: {path}")
            nb = k.n.to_bytes(384, "big")
            eb = k.e.to_bytes((k.e.bit_length() + 7) // 8, "big")
            self._write_log(f"  n = {nb.hex().upper()}")
            self._write_log(f"  e = {eb.hex().upper()}")

    # enrollment

    def _enroll_worker(self, ip, port, user, pw, ch):
        # hash the password, never send it in the clear
        pw_hash  = SHA3_512.new(pw.encode()).digest()
        rpw_hash = SHA3_512.new(pw[::-1].encode()).digest()
        self._log(f"[enroll] H(pw)  = {pw_hash.hex().upper()}")
        self._log(f"[enroll] H(rpw) = {rpw_hash.hex().upper()}")

        # binary payload: [64B H(pw)][64B H(rpw)][1B ulen][username][1B clen][channel]
        # hashes go first so the whole thing fits in rsa-3072 oaep (~254B max)
        ub = user.encode("utf-8")
        cb = ch.encode("utf-8")
        if not 1 <= len(ub) <= 32:
            self._log("[enroll] ERROR: username must be 1-32 bytes")
            self._eq.put(("enroll_done", False))
            return
        payload = pw_hash + rpw_hash + bytes([len(ub)]) + ub + bytes([len(cb)]) + cb

        try:
            ct = PKCS1_OAEP.new(self._pub_enc, hashAlgo=SHA3_512).encrypt(payload)
        except ValueError as ex:
            self._log(f"[enroll] RSA encrypt failed: {ex}")
            self._eq.put(("enroll_done", False))
            return

        self._log(f"[enroll] RSA-OAEP ciphertext = {ct.hex().upper()[:64]}...")

        try:
            sock = socket.create_connection((ip, port), timeout=10)
        except OSError as ex:
            self._log(f"[enroll] can't connect to {ip}:{port}: {ex}")
            self._eq.put(("enroll_done", False))
            return

        try:
            self._net_send(sock, {"type": "REGISTER", "enc_hex": ct.hex().upper()})
            resp = self._net_recv(sock)
        except Exception as ex:
            self._log(f"[enroll] network error: {ex}")
            self._eq.put(("enroll_done", False))
            return
        finally:
            try: sock.close()
            except: pass

        if resp.get("type") != "REG_RESULT":
            self._log(f"[enroll] unexpected response: {resp.get('type')}")
            self._eq.put(("enroll_done", False))
            return

        msg = resp.get("text", "")
        sig = bytes.fromhex(resp.get("sig_hex", ""))
        self._log(f"[enroll] server says: '{msg}'")
        self._log(f"[enroll] signature (first 32B): {sig.hex().upper()[:64]}...")

        # always verify before trusting anything the server sends
        try:
            pkcs1_15.new(self._pub_sig).verify(SHA3_512.new(msg.encode("utf-8")), sig)
            self._log("[enroll] signature OK")
        except Exception:
            self._log("[enroll] SIGNATURE INVALID — discarding response")
            self._eq.put(("enroll_done", False))
            return

        self._eq.put(("enroll_done", msg.startswith("success"), user, ch))

    # login — challenge-response, then stays open for broadcast

    def _login_worker(self, ip, port, user, pw):
        # compute both hashes now -- needed for HMAC and ack decryption
        pw_hash  = SHA3_512.new(pw.encode()).digest()
        rpw_hash = SHA3_512.new(pw[::-1].encode()).digest()

        try:
            sock = socket.create_connection((ip, port), timeout=10)
        except OSError as ex:
            self._log(f"[auth] connect failed: {ex}")
            self._eq.put(("login_done", "network_error"))
            return

        try:
            self._log(f"[auth] LOGIN → '{user}'")
            self._net_send(sock, {"type": "LOGIN", "user": user})

            # server sends back a random challenge nonce
            chal_msg = self._net_recv(sock)
            if chal_msg.get("type") != "CHALLENGE":
                self._log(f"[auth] expected CHALLENGE, got {chal_msg.get('type')!r}")
                sock.close(); self._eq.put(("login_done", "network_error")); return

            nonce = bytes.fromhex(chal_msg["nonce_hex"])
            self._log(f"[auth] challenge nonce = {nonce.hex().upper()}")

            # hmac key = first 32B of H(pw), server derives the same from stored hash
            hmac_k = pw_hash[:32]
            tag    = CryptoHMAC.new(hmac_k, digestmod=SHA3_512)
            tag.update(nonce)
            response = tag.digest()
            self._log(f"[auth] HMAC key      = {hmac_k.hex().upper()}")
            self._log(f"[auth] HMAC response = {response.hex().upper()}")
            self._net_send(sock, {"type": "HMAC_RESP", "mac_hex": response.hex().upper()})

            # get the AES encrypted and RSA signed result
            result = self._net_recv(sock)
            if result.get("type") != "LOGIN_RESULT":
                self._log(f"[auth] expected LOGIN_RESULT, got {result.get('type')!r}")
                sock.close(); self._eq.put(("login_done", "network_error")); return

            ct  = bytes.fromhex(result["ct_hex"])
            sig = bytes.fromhex(result["sig_hex"])
            self._log(f"[auth] result ct  = {ct.hex().upper()[:48]}...")
            self._log(f"[auth] result sig = {sig.hex().upper()[:48]}...")

            # verify signature before decrypting anything
            try:
                pkcs1_15.new(self._pub_sig).verify(SHA3_512.new(ct), sig)
                self._log("[auth] signature verified OK")
            except Exception:
                self._log("[auth] SIGNATURE FAILED — rejecting")
                sock.close(); self._eq.put(("login_done", "auth_failed")); return

            # ack enc key and iv come from H(reversed pw)
            wrap_k  = rpw_hash[:32]
            wrap_iv = rpw_hash[32:48]
            self._log(f"[auth] ack wrap key = {wrap_k.hex().upper()}")
            self._log(f"[auth] ack wrap IV  = {wrap_iv.hex().upper()}")

            try:
                pt = unpad(AES.new(wrap_k, AES.MODE_CBC, wrap_iv).decrypt(ct), 16)
            except ValueError:
                # padding error = wrong key = wrong password
                self._log("[auth] AES decryption failed -- wrong password?")
                sock.close(); self._eq.put(("login_done", "wrong_password")); return

            self._log(f"[auth] decrypted starts: {pt[:32].hex().upper()}...")

        except (ConnectionError, OSError, ValueError) as ex:
            self._log(f"[auth] protocol error: {ex}")
            try: sock.close()
            except: pass
            self._eq.put(("login_done", "network_error"))
            return

        # check which result the server sent back
        if pt.startswith(b"Authentication Successful"):
            rest = pt[len(b"Authentication Successful"):]

            # 1B(ch len) + ch name + aes key(32) + iv(16) + hmac key(32)
            if len(rest) < 2:
                self._log("[auth] success payload too short")
                sock.close(); self._eq.put(("login_done", "auth_failed")); return

            clen    = rest[0]
            ch_name = rest[1:1 + clen].decode("utf-8", errors="replace")
            off     = 1 + clen

            if len(rest) < off + 80:
                self._log(f"[auth] key block too short ({len(rest) - off}B)")
                sock.close(); self._eq.put(("login_done", "auth_failed")); return

            aes_k  = rest[off:off + 32]
            aes_iv = rest[off + 32:off + 48]
            mac_k  = rest[off + 48:off + 80]

            self._log(f"[auth] ✓ channel = {ch_name}")
            self._log(f"[auth] AES key   = {aes_k.hex().upper()}")
            self._log(f"[auth] AES IV    = {aes_iv.hex().upper()}")
            self._log(f"[auth] HMAC key  = {mac_k.hex().upper()}")

            # store session in one dict, easy to wipe on logout
            self._sess = {
                "aes":  aes_k,
                "iv":   aes_iv,
                "mac":  mac_k,
                "ch":   ch_name if ch_name in CHANNELS else None,
                "user": user
            }

            sock.settimeout(None)
            self._conn  = sock
            self._alive = True
            threading.Thread(target=self._listener, daemon=True).start()

            self._eq.put(("login_done", "ok"))
            return

        if pt == b"Authentication Unsuccessful":
            self._log("[auth] server: Authentication Unsuccessful")
            sock.close(); self._eq.put(("login_done", "auth_failed")); return

        if pt == b"Channel Unavailable":
            self._log("[auth] server: Channel Unavailable")
            sock.close(); self._eq.put(("login_done", "channel_unavailable")); return

        self._log(f"[auth] unrecognised plaintext: {pt[:40]!r}")
        sock.close()
        self._eq.put(("login_done", "auth_failed"))

    # broadcast — send and receive

    def _send_msg(self):
        text = self._compose.get().strip()
        if not text:
            return
        if not self._alive or not self._sess:
            self._log("can't send — not logged in")
            return

        try:
            ct = AES.new(
                self._sess["aes"], AES.MODE_CBC, self._sess["iv"]
            ).encrypt(pad(text.encode("utf-8"), 16))

            tag_obj = CryptoHMAC.new(self._sess["mac"], digestmod=SHA3_512)
            tag_obj.update(ct)
            tag = tag_obj.digest()

            self._log(f"[send] ct  = {ct.hex().upper()[:48]}...")
            self._log(f"[send] mac = {tag.hex().upper()}")

            self._net_send(self._conn, {
                "type":    "MSG",
                "ct_hex":  ct.hex().upper(),
                "mac_hex": tag.hex().upper()
            })
            self._compose.set("")
        except (OSError, ConnectionError) as ex:
            self._log(f"[send] failed: {ex}")
            self._shutdown()

    def _listener(self):
        # background receive loop, runs until disconnected
        while self._alive:
            try:
                msg = self._net_recv(self._conn)
            except:
                self._eq.put(("disconnected",))
                return

            if msg.get("type") != "MSG":
                self._log(f"[recv] unexpected type: {msg.get('type')!r}")
                continue

            sender = msg.get("sender", "?")
            ct  = bytes.fromhex(msg.get("ct_hex", ""))
            tag = bytes.fromhex(msg.get("mac_hex", ""))
            self._log(f"[recv] '{sender}': ct = {ct.hex().upper()[:32]}...")

            # check hmac before decrypting anything
            try:
                chk = CryptoHMAC.new(self._sess["mac"], digestmod=SHA3_512)
                chk.update(ct)
                chk.verify(tag)
            except Exception:
                self._log(f"[recv] HMAC invalid — dropping message from '{sender}'")
                self._eq.put(("incoming", sender, "<<HMAC INVALID — dropped>>"))
                continue

            try:
                pt = unpad(
                    AES.new(self._sess["aes"], AES.MODE_CBC, self._sess["iv"]).decrypt(ct),
                    16
                )
                text = pt.decode("utf-8")
            except Exception:
                self._log(f"[recv] decryption error from '{sender}'")
                self._eq.put(("incoming", sender, "<<DECRYPTION FAILED>>"))
                continue

            self._log(f"[recv] '{sender}': {text}")
            self._eq.put(("incoming", sender, text))

    # session teardown

    def _shutdown(self):
        if not self._alive:
            return
        self._alive = False
        if self._conn:
            try: self._conn.close()
            except: pass
        self._conn = None
        self._sess = None
        self._eq.put(("disconnected",))  # notify main thread

    def _disconnect(self):
        if self._alive and self._conn:
            try:
                self._net_send(self._conn, {"type": "BYE"})
            except: pass
        self._shutdown()

    # _log() queues the message so its safe to call from any thread

    def _log(self, text):
        self._eq.put(("log", text))

    def _write_log(self, text):
        # direct write, only call from main thread
        self._log_box.insert(tk.END, text + "\n")
        self._log_box.see(tk.END)

    # process queue events, reschedules itself every 40ms

    def _tick(self):
        try:
            while True:
                ev = self._eq.get_nowait()
                kind = ev[0]

                if kind == "log":
                    self._write_log(ev[1])

                elif kind == "incoming":
                    _, sender, text = ev
                    self._msg_box.configure(state=tk.NORMAL)
                    self._msg_box.insert(tk.END, f"[{sender}]  {text}\n")
                    self._msg_box.see(tk.END)
                    self._msg_box.configure(state=tk.DISABLED)

                elif kind == "enroll_done":
                    ok = ev[1]
                    if ok:
                        user, ch = ev[2], ev[3]
                        messagebox.showinfo("Enrolled", f"'{user}' registered on {ch}")
                    else:
                        messagebox.showerror("Enrollment failed", "Check the crypto log.")
                    self._v_rpass.set("")

                elif kind == "login_done":
                    self._on_login_result(ev[1])

                elif kind == "disconnected":
                    self._on_disconnected()

        except queue.Empty:
            pass

        self.root.after(40, self._tick)

    # button clicks

    def _btn_load_keys(self):
        if not self._v_enc.get() or not self._v_sig.get():
            messagebox.showerror("Missing files", "Select both PEM files first.")
            return
        try:
            self._load_keys(self._v_enc.get(), self._v_sig.get())
        except Exception as ex:
            messagebox.showerror("Load failed", str(ex))

    def _btn_enroll(self):
        ip, port = self._get_addr() or (None, None)
        if ip is None:
            return
        if not self._pub_enc:
            messagebox.showerror("Keys not loaded", "Load server keys first.")
            return
        user = self._v_ruser.get().strip()
        pw   = self._v_rpass.get()
        ch   = self._v_rchan.get()
        if not user or not pw:
            messagebox.showerror("Missing input", "Username and password required.")
            return
        threading.Thread(
            target=self._enroll_worker,
            args=(ip, port, user, pw, ch),
            daemon=True
        ).start()

    def _btn_login(self):
        ip, port = self._get_addr() or (None, None)
        if ip is None:
            return
        if not self._pub_sig:
            messagebox.showerror("Keys not loaded", "Load server keys first.")
            return
        user = self._v_luser.get().strip()
        pw   = self._v_lpass.get()
        if not user or not pw:
            messagebox.showerror("Missing input", "Username and password required.")
            return
        self._login_btn.configure(state=tk.DISABLED)
        self._set_status("● Authenticating...", C_ACC)
        threading.Thread(
            target=self._login_worker,
            args=(ip, port, user, pw),
            daemon=True
        ).start()

    def _btn_disconnect(self):
        self._disconnect()

    def _get_addr(self):
        ip = self._v_ip.get().strip()
        try:
            port = int(self._v_port.get())
            if not 1 <= port <= 65535:
                raise ValueError
        except ValueError:
            messagebox.showerror("Bad port", "Port must be 1–65535.")
            return None
        return ip, port

    # UI state changes

    def _on_login_result(self, result):
        self._v_lpass.set("")
        if result == "ok":
            ch   = self._sess["ch"] if self._sess else "?"
            user = self._sess["user"] if self._sess else "?"
            self._v_chanl.set(ch or "?")
            self._send_btn.configure(state=tk.NORMAL)
            self._disc_btn.configure(state=tk.NORMAL)
            self._login_btn.configure(state=tk.DISABLED)
            self._set_status(f"● {user} @ {ch}", C_OK)
        elif result == "wrong_password":
            messagebox.showerror("Wrong password",
                                 "Decryption failed — check your password.")
            self._set_status("● Not connected", C_ERR)
            self._login_btn.configure(state=tk.NORMAL)
        elif result == "auth_failed":
            messagebox.showerror("Auth failed",
                                 "Server rejected the credentials.")
            self._set_status("● Not connected", C_ERR)
            self._login_btn.configure(state=tk.NORMAL)
        elif result == "channel_unavailable":
            messagebox.showwarning("Channel not ready",
                                   "Server hasn't generated keys for this channel yet.")
            self._set_status("● Not connected", C_ERR)
            self._login_btn.configure(state=tk.NORMAL)
        else:
            messagebox.showerror("Connection error",
                                 "Could not reach the server. See crypto log.")
            self._set_status("● Not connected", C_ERR)
            self._login_btn.configure(state=tk.NORMAL)

    def _on_disconnected(self):
        self._set_status("● Not connected", C_ERR)
        self._send_btn.configure(state=tk.DISABLED)
        self._login_btn.configure(state=tk.NORMAL)
        self._disc_btn.configure(state=tk.DISABLED)
        self._v_chanl.set("—")
        self._alive = False
        self._conn  = None
        self._sess  = None

    def _set_status(self, text, color=C_ERR):
        self._v_stat.set(text)
        self._status_badge.configure(fg=color)

    # build the window

    def _build(self):
        # top banner
        banner = tk.Frame(self.root, bg=C_ACC, height=58)
        banner.pack(fill=tk.X)
        banner.pack_propagate(False)
        tk.Label(banner, text="  CLIENT", bg=C_ACC, fg=C_CARD,
                 font=(FONT[0], 17, "bold")).pack(side=tk.LEFT, padx=18)
        tk.Label(banner, text="CS432 Secure Channel", bg=C_ACC, fg=C_BG,
                 font=(FONT[0], 10)).pack(side=tk.LEFT, padx=4)
        self._status_badge = tk.Label(
            banner, textvariable=self._v_stat,
            bg=C_CARD, fg=C_ERR, font=(FONT[0], 9, "bold"), padx=10, pady=4)
        self._status_badge.pack(side=tk.RIGHT, padx=18, pady=10)

        body = tk.Frame(self.root, bg=C_BG)
        body.pack(fill=tk.BOTH, expand=True, padx=10, pady=8)

        # left column — form panels
        left = tk.Frame(body, bg=C_BG)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 8))

        # key loading
        kf = ttk.LabelFrame(left, text="SERVER KEYS & CONNECTION")
        kf.pack(fill=tk.X, pady=(0, 6))

        def field(parent, label, var, row, pw=False, browse=None):
            ttk.Label(parent, text=label, style="Card.TLabel").grid(
                row=row, column=0, sticky="e", padx=(10, 4), pady=4)
            kw = {"show": "*"} if pw else {}
            ttk.Entry(parent, textvariable=var, width=28, **kw).grid(
                row=row, column=1, sticky="we", padx=4)
            if browse:
                ttk.Button(parent, text="…", command=browse, width=3).grid(
                    row=row, column=2, padx=(0, 8))

        field(kf, "Enc PEM:",   self._v_enc,  0,
              browse=lambda: self._v_enc.set(
                  filedialog.askopenfilename(title="Enc public key",
                  filetypes=[("PEM","*.pem"),("All","*.*")]) or self._v_enc.get()))
        field(kf, "Sig PEM:",   self._v_sig,  1,
              browse=lambda: self._v_sig.set(
                  filedialog.askopenfilename(title="Sig public key",
                  filetypes=[("PEM","*.pem"),("All","*.*")]) or self._v_sig.get()))
        field(kf, "Server IP:", self._v_ip,   2)
        field(kf, "Port:",      self._v_port, 3)
        kf.columnconfigure(1, weight=1)
        ttk.Button(kf, text="Load Keys",
                   command=self._btn_load_keys).grid(
            row=4, column=0, columnspan=3, sticky="we", padx=10, pady=(4, 10))

        # enrollment
        ef = ttk.LabelFrame(left, text="ENROLLMENT")
        ef.pack(fill=tk.X, pady=(0, 6))
        field(ef, "Username:", self._v_ruser, 0)
        field(ef, "Password:", self._v_rpass, 1, pw=True)
        ttk.Label(ef, text="Channel:", style="Card.TLabel").grid(
            row=2, column=0, sticky="e", padx=(10, 4), pady=4)
        ttk.Combobox(ef, textvariable=self._v_rchan, values=list(CHANNELS),
                     state="readonly", width=14).grid(row=2, column=1,
                                                      sticky="w", padx=4)
        ef.columnconfigure(1, weight=1)
        ttk.Button(ef, text="Enroll",
                   command=self._btn_enroll).grid(
            row=3, column=0, columnspan=3, sticky="we", padx=10, pady=(4, 10))

        # login
        lf = ttk.LabelFrame(left, text="LOGIN")
        lf.pack(fill=tk.X, pady=(0, 6))
        field(lf, "Username:", self._v_luser, 0)
        field(lf, "Password:", self._v_lpass, 1, pw=True)
        lf.columnconfigure(1, weight=1)
        btn_row = tk.Frame(lf, bg=C_CARD)
        btn_row.grid(row=2, column=0, columnspan=3, sticky="we",
                     padx=10, pady=(4, 10))
        self._login_btn = ttk.Button(btn_row, text="Login",
                                     command=self._btn_login)
        self._login_btn.pack(side=tk.LEFT, padx=(0, 6))
        self._disc_btn = ttk.Button(btn_row, text="Disconnect",
                                    command=self._btn_disconnect,
                                    state=tk.DISABLED)
        self._disc_btn.pack(side=tk.LEFT)

        # channel indicator
        ci = tk.Frame(left, bg=C_BAND, padx=10, pady=6)
        ci.pack(fill=tk.X, pady=(0, 6))
        tk.Label(ci, text="Channel:", bg=C_BAND, fg=C_DARK,
                 font=(FONT[0], 9)).pack(side=tk.LEFT)
        tk.Label(ci, textvariable=self._v_chanl, bg=C_BAND, fg=C_DARK,
                 font=(FONT[0], 9, "bold")).pack(side=tk.LEFT, padx=(4, 0))

        # right side — notebook
        nb = ttk.Notebook(body)
        nb.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # messages tab
        chat = ttk.Frame(nb)
        # send bar goes first or the text widget expands and hides it
        send_bar = tk.Frame(chat, bg=C_BAND)
        send_bar.pack(side=tk.BOTTOM, fill=tk.X)
        self._compose = tk.StringVar()
        self._compose_entry = ttk.Entry(send_bar, textvariable=self._compose)
        self._compose_entry.pack(side=tk.LEFT, fill=tk.X, expand=True,
                                 padx=(8, 4), pady=8)
        self._compose_entry.bind("<Return>", lambda _: self._send_msg())
        self._send_btn = ttk.Button(send_bar, text="Send ▶",
                                    command=self._send_msg, state=tk.DISABLED)
        self._send_btn.pack(side=tk.LEFT, padx=(0, 8), pady=8)

        msg_scr = ttk.Scrollbar(chat)
        msg_scr.pack(side=tk.RIGHT, fill=tk.Y)
        self._msg_box = tk.Text(chat, wrap=tk.WORD, state=tk.DISABLED,
                                bg=C_CARD, fg=C_INK, relief="flat",
                                borderwidth=0, font=FONT, padx=10, pady=8,
                                yscrollcommand=msg_scr.set)
        self._msg_box.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        msg_scr.configure(command=self._msg_box.yview)
        nb.add(chat, text="  Messages  ")

        # crypto log tab
        logf = ttk.Frame(nb)
        log_scr = ttk.Scrollbar(logf)
        log_scr.pack(side=tk.RIGHT, fill=tk.Y)
        self._log_box = tk.Text(logf, wrap=tk.WORD, bg=C_CARD, fg=C_SUB,
                                relief="flat", borderwidth=0, font=MONO,
                                padx=8, pady=6,
                                yscrollcommand=log_scr.set)
        self._log_box.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        log_scr.configure(command=self._log_box.yview)
        nb.add(logf, text="  Crypto Log  ")

    def _quit(self):
        try: self._disconnect()
        except: pass
        self.root.destroy()

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    SecureClient().run()
