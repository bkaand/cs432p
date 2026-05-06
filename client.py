"""
secure channel client — cs432 project
enrollment, auth, broadcast recv/send + tkinter gui
"""

import queue
import socket
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import crypto_utils as cu


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
        self.session_aes_key = None     # channel aes key
        self.session_iv = None
        self.session_hmac_key = None

        self._recv_thread = None
        self._connected = False         # true once in broadcast phase

    def load_server_pubkeys(self, enc_path: str, sign_path: str) -> None:
        self.server_enc_pub = cu.load_rsa_key_from_file(enc_path)
        self.server_sign_pub = cu.load_rsa_key_from_file(sign_path)
        self.log_cb(f"Loaded server enc public key from: {enc_path}")
        self.log_cb(f"  modulus n (hex): {cu.to_hex(self.server_enc_pub.n.to_bytes(384, 'big'))}")
        self.log_cb(f"  public  e (hex): {cu.to_hex(self.server_enc_pub.e.to_bytes((self.server_enc_pub.e.bit_length() + 7) // 8, 'big'))}")
        self.log_cb(f"Loaded server sign public key from: {sign_path}")
        self.log_cb(f"  modulus n (hex): {cu.to_hex(self.server_sign_pub.n.to_bytes(384, 'big'))}")
        self.log_cb(f"  public  e (hex): {cu.to_hex(self.server_sign_pub.e.to_bytes((self.server_sign_pub.e.bit_length() + 7) // 8, 'big'))}")

    def enroll(self, ip: str, port: int, username: str, password: str, channel: str) -> bool:
        """enroll the user. returns True if it worked."""
        if self.server_enc_pub is None or self.server_sign_pub is None:
            self.log_cb("ERROR: Server public keys not loaded.")
            return False
        if channel not in cu.CHANNELS:
            self.log_cb(f"ERROR: invalid channel: {channel}")
            return False

        # derive password hashes
        h_pw, h_rev_pw = cu.password_hashes(password)
        self.log_cb(f"[Enrollment] SHA3-512(password):           {cu.to_hex(h_pw)}")
        self.log_cb(f"[Enrollment] SHA3-512(reversed password):  {cu.to_hex(h_rev_pw)}")

        # pack into binary, has to fit in rsa-3072+oaep
        payload = cu.encode_enrollment(username, h_pw, h_rev_pw, channel)

        ct = cu.rsa_encrypt(self.server_enc_pub, payload)
        self.log_cb(f"[Enrollment] RSA-OAEP encrypted payload: {cu.short_hex(ct)}")

        try:
            sock = socket.create_connection((ip, port), timeout=10)
        except OSError as e:
            self.log_cb(f"[Enrollment] Connection failed: {e}")
            return False

        try:
            cu.send_msg(sock, {"type": "ENROLL_REQ", "payload_hex": cu.to_hex(ct)})
            resp = cu.recv_msg(sock)
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
        sig = cu.from_hex(resp.get("signature_hex", ""))
        self.log_cb(f"[Enrollment] Server response: '{message}'")
        self.log_cb(f"[Enrollment] Signature: {cu.short_hex(sig)}")

        if not cu.rsa_verify(self.server_sign_pub, message.encode("utf-8"), sig):
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
            # send auth request
            self.log_cb(f"[Auth] Sending AUTH_REQ for username '{username}'")
            cu.send_msg(sock, {"type": "AUTH_REQ", "username": username})

            # wait for challenge
            chal_msg = cu.recv_msg(sock)
            if chal_msg.get("type") != "AUTH_CHALLENGE":
                self.log_cb(f"[Auth] Unexpected: {chal_msg}")
                sock.close()
                return "network_error"

            challenge = cu.from_hex(chal_msg["challenge_hex"])
            self.log_cb(f"[Auth] Received 128-bit challenge: {cu.to_hex(challenge)}")

            # hmac the challenge with lower half of h(pw)
            h_pw, h_rev_pw = cu.password_hashes(password)
            hmac_key = cu.derive_hmac_key_from_hash(h_pw)
            mac = cu.hmac_sha3_512(hmac_key, challenge)
            self.log_cb(f"[Auth] HMAC key (lower half h(pw)): {cu.to_hex(hmac_key)}")
            self.log_cb(f"[Auth] Sending HMAC-SHA3-512:        {cu.to_hex(mac)}")
            cu.send_msg(sock, {"type": "AUTH_HMAC", "hmac_hex": cu.to_hex(mac)})

            # get the result
            res = cu.recv_msg(sock)
            if res.get("type") != "AUTH_RESULT":
                self.log_cb(f"[Auth] Unexpected result message: {res}")
                sock.close()
                return "network_error"

            ct = cu.from_hex(res["ciphertext_hex"])
            sig = cu.from_hex(res["signature_hex"])
            self.log_cb(f"[Auth] Result ciphertext: {cu.short_hex(ct)}")
            self.log_cb(f"[Auth] Result signature:  {cu.short_hex(sig)}")

            # verify sig before touching the ciphertext
            if not cu.rsa_verify(self.server_sign_pub, ct, sig):
                self.log_cb("[Auth] SIGNATURE INVALID on AUTH_RESULT. Discarding.")
                sock.close()
                return "auth_failed"
            self.log_cb("[Auth] Signature on result verified OK.")

            # decrypt with key derived from h(rev_pw)
            ack_key, ack_iv = cu.derive_aes_key_iv_from_hash(h_rev_pw)
            self.log_cb(f"[Auth] AES key for ack decryption: {cu.to_hex(ack_key)}")
            self.log_cb(f"[Auth] IV  for ack decryption:    {cu.to_hex(ack_iv)}")

            try:
                pt = cu.aes_decrypt(ack_key, ack_iv, ct)
            except ValueError:
                self.log_cb("[Auth] AES decryption failed (likely wrong password).")
                sock.close()
                return "wrong_password"

            self.log_cb(f"[Auth] Decrypted plaintext (first 64 bytes hex): {cu.to_hex(pt[:64])}")

            if pt.startswith(cu.AUTH_OK_TEXT):
                tail = pt[len(cu.AUTH_OK_TEXT):]
                fixed_len = cu.AES_KEY_LEN + cu.AES_BLOCK_SIZE + cu.HMAC_KEY_LEN
                if len(tail) < fixed_len:
                    self.log_cb(f"[Auth] Unexpected tail length: {len(tail)} bytes.")
                    sock.close()
                    return "auth_failed"

                aes_key = tail[: cu.AES_KEY_LEN]
                iv = tail[cu.AES_KEY_LEN: cu.AES_KEY_LEN + cu.AES_BLOCK_SIZE]
                hmac_key_ch = tail[cu.AES_KEY_LEN + cu.AES_BLOCK_SIZE: fixed_len]
                channel_bytes = tail[fixed_len:]
                try:
                    channel_name = channel_bytes.decode("utf-8")
                except UnicodeDecodeError:
                    channel_name = ""

                self.session_aes_key = aes_key
                self.session_iv = iv
                self.session_hmac_key = hmac_key_ch
                self.username = username
                self.channel = channel_name if channel_name in cu.CHANNELS else None

                self.log_cb("[Auth] Authentication Successful.")
                self.log_cb(f"[Auth] Channel:          {channel_name}")
                self.log_cb(f"[Auth] Channel AES key:  {cu.to_hex(aes_key)}")
                self.log_cb(f"[Auth] Channel IV:       {cu.to_hex(iv)}")
                self.log_cb(f"[Auth] Channel HMAC key: {cu.to_hex(hmac_key_ch)}")

                # keep socket open for broadcast phase
                # clear the timeout — create_connection sets it on the socket itself,
                # not just connect. leaving it would kill us on every idle interval.
                sock.settimeout(None)
                self.sock = sock
                self._connected = True
                # channel comes from the auth payload
                self._recv_thread = threading.Thread(target=self._receive_loop, daemon=True)
                self._recv_thread.start()
                return "ok"

            if pt == cu.AUTH_FAIL_TEXT:
                self.log_cb("[Auth] Server reported: Authentication Unsuccessful.")
                sock.close()
                return "auth_failed"

            if pt == cu.AUTH_CHANNEL_UNAVAILABLE:
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
            ct = cu.aes_encrypt(self.session_aes_key, self.session_iv, message.encode("utf-8"))
            mac = cu.hmac_sha3_512(self.session_hmac_key, ct)
            self.log_cb(f"[Send] AES-CBC ciphertext: {cu.short_hex(ct)}")
            self.log_cb(f"[Send] HMAC:               {cu.short_hex(mac)}")
            cu.send_msg(
                self.sock,
                {
                    "type": "BROADCAST",
                    "ciphertext_hex": cu.to_hex(ct),
                    "hmac_hex": cu.to_hex(mac),
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
                msg = cu.recv_msg(self.sock)
            except (ConnectionError, OSError, ValueError):
                self._mark_disconnected()
                return
            if msg.get("type") != "BROADCAST":
                self.log_cb(f"[Recv] Unexpected type: {msg.get('type')}")
                continue

            sender = msg.get("from", "?")
            ct = cu.from_hex(msg.get("ciphertext_hex", ""))
            mac = cu.from_hex(msg.get("hmac_hex", ""))

            self.log_cb(f"[Recv] from '{sender}': ct={cu.short_hex(ct)} hmac={cu.short_hex(mac)}")

            if not cu.hmac_verify(self.session_hmac_key, ct, mac):
                self.log_cb(f"[Recv] HMAC INVALID for message from '{sender}'. Discarded.")
                self.message_cb(sender, "<<INVALID HMAC — message discarded>>")
                continue
            try:
                pt = cu.aes_decrypt(self.session_aes_key, self.session_iv, ct)
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
                cu.send_msg(self.sock, {"type": "DISCONNECT"})
            except (OSError, ConnectionError):
                pass
        self._mark_disconnected()


# --- gui ---
class ClientGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("CS432 Project — Secure Channel Client")
        self.root.geometry("1050x780")

        # queue for cross-thread updates
        self._gui_q = queue.Queue()
        self.root.after(50, self._poll_gui_queue)

        # form vars
        self._enc_pub_path = tk.StringVar()
        self._sign_pub_path = tk.StringVar()
        self._ip_var = tk.StringVar(value="127.0.0.1")
        self._port_var = tk.StringVar(value="6000")

        self._reg_user = tk.StringVar()
        self._reg_pass = tk.StringVar()
        self._reg_channel = tk.StringVar(value=cu.CHANNELS[0])

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
        pad = {"padx": 6, "pady": 4}

        # keys + connection at top
        top = ttk.LabelFrame(self.root, text="Server keys & connection")
        top.pack(fill=tk.X, **pad)

        ttk.Label(top, text="Enc public key (PEM):").grid(row=0, column=0, sticky="e", padx=4, pady=2)
        ttk.Entry(top, textvariable=self._enc_pub_path, width=70).grid(row=0, column=1, columnspan=2, sticky="we")
        ttk.Button(top, text="Browse", command=self._browse_enc_pub).grid(row=0, column=3, padx=4)

        ttk.Label(top, text="Sign public key (PEM):").grid(row=1, column=0, sticky="e", padx=4, pady=2)
        ttk.Entry(top, textvariable=self._sign_pub_path, width=70).grid(row=1, column=1, columnspan=2, sticky="we")
        ttk.Button(top, text="Browse", command=self._browse_sign_pub).grid(row=1, column=3, padx=4)

        ttk.Label(top, text="Server IP:").grid(row=2, column=0, sticky="e", padx=4, pady=2)
        ttk.Entry(top, textvariable=self._ip_var, width=20).grid(row=2, column=1, sticky="w")
        ttk.Label(top, text="Port:").grid(row=2, column=2, sticky="e", padx=4)
        ttk.Entry(top, textvariable=self._port_var, width=8).grid(row=2, column=3, sticky="w")

        ttk.Button(top, text="Load server keys", command=self._on_load_keys).grid(
            row=3, column=0, columnspan=4, sticky="we", padx=4, pady=4
        )

        actions = ttk.Frame(self.root)
        actions.pack(fill=tk.X, **pad)

        # Enrollment
        enr = ttk.LabelFrame(actions, text="Enrollment")
        enr.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        ttk.Label(enr, text="Username:").grid(row=0, column=0, sticky="e", padx=4, pady=2)
        ttk.Entry(enr, textvariable=self._reg_user, width=20).grid(row=0, column=1, sticky="w")
        ttk.Label(enr, text="Password:").grid(row=1, column=0, sticky="e", padx=4, pady=2)
        ttk.Entry(enr, textvariable=self._reg_pass, width=20, show="*").grid(row=1, column=1, sticky="w")
        ttk.Label(enr, text="Channel:").grid(row=2, column=0, sticky="e", padx=4, pady=2)
        ttk.Combobox(enr, textvariable=self._reg_channel, values=list(cu.CHANNELS), state="readonly", width=18).grid(row=2, column=1, sticky="w")
        ttk.Button(enr, text="Enroll", command=self._on_enroll).grid(row=3, column=0, columnspan=2, sticky="we", padx=4, pady=4)

        # Login
        log_f = ttk.LabelFrame(actions, text="Login")
        log_f.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        ttk.Label(log_f, text="Username:").grid(row=0, column=0, sticky="e", padx=4, pady=2)
        ttk.Entry(log_f, textvariable=self._login_user, width=20).grid(row=0, column=1, sticky="w")
        ttk.Label(log_f, text="Password:").grid(row=1, column=0, sticky="e", padx=4, pady=2)
        ttk.Entry(log_f, textvariable=self._login_pass, width=20, show="*").grid(row=1, column=1, sticky="w")
        self._login_btn = ttk.Button(log_f, text="Login", command=self._on_login)
        self._login_btn.grid(row=3, column=0, sticky="we", padx=4, pady=4)
        self._disconnect_btn = ttk.Button(log_f, text="Disconnect", command=self._on_disconnect, state=tk.DISABLED)
        self._disconnect_btn.grid(row=3, column=1, sticky="we", padx=4, pady=4)

        # status bar
        self._status_var = tk.StringVar(value="Status: not connected")
        ttk.Label(self.root, textvariable=self._status_var, foreground="#0a0").pack(fill=tk.X, padx=8)

        nb = ttk.Notebook(self.root)
        nb.pack(fill=tk.BOTH, expand=True, **pad)

        ch_frame = ttk.Frame(nb)
        self._ch_label = ttk.Label(ch_frame, text="Channel: (not authenticated)", font=("TkDefaultFont", 11, "bold"))
        self._ch_label.pack(anchor="w", padx=6, pady=4)

        msg_box = ttk.Frame(ch_frame)
        msg_box.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        self._messages_widget = tk.Text(msg_box, wrap=tk.WORD, height=20, state=tk.DISABLED)
        scr = ttk.Scrollbar(msg_box, command=self._messages_widget.yview)
        self._messages_widget.configure(yscrollcommand=scr.set)
        self._messages_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scr.pack(side=tk.RIGHT, fill=tk.Y)

        send_box = ttk.Frame(ch_frame)
        send_box.pack(fill=tk.X, padx=4, pady=4)
        self._compose_var = tk.StringVar()
        self._compose_entry = ttk.Entry(send_box, textvariable=self._compose_var)
        self._compose_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        self._compose_entry.bind("<Return>", lambda _e: self._on_send())
        self._send_btn = ttk.Button(send_box, text="Send", command=self._on_send, state=tk.DISABLED)
        self._send_btn.pack(side=tk.LEFT, padx=4)

        nb.add(ch_frame, text="Channel")

        log_frame = ttk.Frame(nb)
        self._log_widget = tk.Text(log_frame, wrap=tk.WORD, height=20)
        scrl = ttk.Scrollbar(log_frame, command=self._log_widget.yview)
        self._log_widget.configure(yscrollcommand=scrl.set)
        self._log_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrl.pack(side=tk.RIGHT, fill=tk.Y)
        nb.add(log_frame, text="Crypto Log")

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
        if channel not in cu.CHANNELS:
            messagebox.showerror("Bad channel", "Channel must be IF100 / MATH101 / SPS101.")
            return

        # run in a thread so we don't freeze the gui
        def worker():
            ok = self.core.enroll(ip, port, username, password, channel)
            if ok:
                self._gui_q.put(("info", "Enrollment success", f"User '{username}' enrolled on {channel}."))
            else:
                self._gui_q.put(("error", "Enrollment failed", "See the log for details."))
            # clear the password field
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

        # disable button while we're working
        self._login_btn.configure(state=tk.DISABLED)
        self._set_status(f"Status: authenticating as '{username}'...")

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

    # thread-safe updates
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
            self._set_status("Status: not connected")
            self._send_btn.configure(state=tk.DISABLED)
            self._login_btn.configure(state=tk.NORMAL)
            self._disconnect_btn.configure(state=tk.DISABLED)
            self._ch_label.configure(text="Channel: (not authenticated)")

    def _handle_login_result(self, result: str, username: str):
        if result == "ok":
            # channel is set from the auth payload
            channel = self.core.channel  # might be None
            self._login_user.set(username)
            self._send_btn.configure(state=tk.NORMAL)
            self._disconnect_btn.configure(state=tk.NORMAL)
            self._login_btn.configure(state=tk.DISABLED)
            ch_text = channel if channel else "(authenticated)"
            self._ch_label.configure(text=f"Channel: {ch_text}")
            self._set_status(f"Status: connected as '{username}'")
        elif result == "wrong_password":
            messagebox.showerror("Wrong password", "Decryption failed; the password is likely wrong.")
            self._set_status("Status: not connected")
            self._login_btn.configure(state=tk.NORMAL)
        elif result == "auth_failed":
            messagebox.showerror("Authentication failed", "Server rejected the login.")
            self._set_status("Status: not connected")
            self._login_btn.configure(state=tk.NORMAL)
        elif result == "channel_unavailable":
            messagebox.showwarning("Channel unavailable", "The channel keys have not been generated on the server yet.")
            self._set_status("Status: not connected")
            self._login_btn.configure(state=tk.NORMAL)
        else:
            messagebox.showerror("Network error", "Could not reach server. See log.")
            self._set_status("Status: not connected")
            self._login_btn.configure(state=tk.NORMAL)

    def _set_status(self, s: str):
        self._status_var.set(s)

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    ClientGUI().run()