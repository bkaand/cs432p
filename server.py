"""
server.py
---------
CS432 Project — Secure Channel Broadcast Server

Implements:
    * Enrollment (RSA-OAEP encrypted requests, signed responses)
    * Authentication via challenge-response (HMAC over a 128-bit nonce)
    * Per-channel master-secret-derived AES/HMAC keys (IF100, MATH101, SPS101)
    * Encrypted-and-signed authentication acknowledgments
    * Encrypted broadcast relay (server does NOT decrypt or verify)
    * Persistent enrollment database in JSON
    * Tkinter GUI with full per-channel and master log

Run:
    python3 server.py
"""

import json
import os
import queue
import socket
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import crypto_utils as cu


# Default file name for the persistent enrollment store
ENROLLMENT_DB_FILE = "server_enrollments.json"


# =============================================================================
# Server core (network + protocol logic)
# =============================================================================
class SecureChannelServer:
    """
    Holds the protocol state for the server: enrollment DB, channel keys,
    active connections. The Tk GUI drives this object via methods, and this
    object reports activity through a logging callback (`log_cb`) and a
    structured-event callback (`event_cb`) used by the GUI.
    """

    def __init__(self, log_cb, event_cb):
        # log_cb(target: str, message: str)
        # target is one of {"server", "IF100", "MATH101", "SPS101"}
        self.log_cb = log_cb
        # event_cb(name: str, payload: dict) for GUI side-effects (online list etc.)
        self.event_cb = event_cb

        # RSA key objects
        self.enc_dec_key = None       # private+public, for decrypting enrollment & encrypting responses
        self.sign_key = None          # private+public, for signing

        # Listening socket and thread
        self._listen_sock = None
        self._listen_thread = None
        self._running = False

        # Persistent enrollment DB:
        #   {username: {h_pw_hex, h_rev_pw_hex, channel}}
        self._db_lock = threading.Lock()
        self.enrollments = self._load_db()

        # Per-channel keys (set via "Generate Keys" GUI buttons):
        #   {channel: {"aes_key": bytes, "iv": bytes, "hmac_key": bytes,
        #              "master_hex": str (for display)}}
        self._channel_lock = threading.Lock()
        self.channel_keys = {}

        # Active authenticated clients:
        #   {username: {"sock": socket, "channel": str, "addr": (ip, port)}}
        self._conn_lock = threading.Lock()
        self.active = {}

    # -------------------------------------------------------------------------
    # Persistent enrollment DB
    # -------------------------------------------------------------------------
    def _load_db(self):
        if not os.path.exists(ENROLLMENT_DB_FILE):
            return {}
        try:
            with open(ENROLLMENT_DB_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            return {}

    def _persist_db(self):
        with open(ENROLLMENT_DB_FILE, "w", encoding="utf-8") as f:
            json.dump(self.enrollments, f, indent=2)

    # -------------------------------------------------------------------------
    # RSA key loading
    # -------------------------------------------------------------------------
    def load_rsa_keys(self, enc_dec_path: str, sign_path: str) -> None:
        """Load the server's two RSA-3072 key pairs from PEM files."""
        self.enc_dec_key = cu.load_rsa_key_from_file(enc_dec_path)
        self.sign_key = cu.load_rsa_key_from_file(sign_path)
        self.log_cb("server", f"Loaded enc/dec key from: {enc_dec_path}")
        self.log_cb("server", f"  modulus n  (hex): {cu.to_hex(self.enc_dec_key.n.to_bytes(384, 'big'))}")
        self.log_cb("server", f"  public  e  (hex): {cu.to_hex(self.enc_dec_key.e.to_bytes((self.enc_dec_key.e.bit_length() + 7) // 8, 'big'))}")
        self.log_cb("server", f"  private d  (hex): {cu.to_hex(self.enc_dec_key.d.to_bytes(384, 'big'))}")
        self.log_cb("server", f"Loaded sign/verify key from: {sign_path}")
        self.log_cb("server", f"  modulus n  (hex): {cu.to_hex(self.sign_key.n.to_bytes(384, 'big'))}")
        self.log_cb("server", f"  public  e  (hex): {cu.to_hex(self.sign_key.e.to_bytes((self.sign_key.e.bit_length() + 7) // 8, 'big'))}")
        self.log_cb("server", f"  private d  (hex): {cu.to_hex(self.sign_key.d.to_bytes(384, 'big'))}")

    # -------------------------------------------------------------------------
    # Channel key generation (server-only, in-memory)
    # -------------------------------------------------------------------------
    def generate_channel_keys(self, channel: str, master_secret: str) -> None:
        """
        Deterministically derive AES-256 key, IV, and HMAC key for one channel.
            h  = SHA3-512(master_secret)
            aes_key = h[0:32], iv = h[32:48], (h[48:64] discarded)
            hr = SHA3-512(reverse(master_secret))
            hmac_key = hr[0:32]
        Once generated for a channel, the keys are FIXED for the lifetime of the
        server (re-generation is rejected to satisfy the spec).
        """
        if channel not in cu.CHANNELS:
            raise ValueError(f"Unknown channel: {channel}")

        with self._channel_lock:
            if channel in self.channel_keys:
                self.log_cb(
                    "server",
                    f"[{channel}] Keys already generated. They cannot be changed "
                    f"during the lifetime of the server (per spec).",
                )
                return

            h = cu.sha3_512(master_secret.encode("utf-8"))
            hr = cu.sha3_512(cu.reverse_str(master_secret).encode("utf-8"))
            aes_key, iv = cu.derive_aes_key_iv_from_hash(h)
            hmac_key = cu.derive_hmac_key_from_hash(hr)

            self.channel_keys[channel] = {
                "aes_key": aes_key,
                "iv": iv,
                "hmac_key": hmac_key,
                "master_hex": cu.to_hex(h),
            }

        self.log_cb(channel, f"Master secret hash (SHA3-512): {cu.to_hex(h)}")
        self.log_cb(channel, f"Derived AES-256 key:  {cu.to_hex(aes_key)}")
        self.log_cb(channel, f"Derived AES IV:       {cu.to_hex(iv)}")
        self.log_cb(channel, f"Derived HMAC key:     {cu.to_hex(hmac_key)}")
        self.event_cb("channel_keys_ready", {"channel": channel})

    # -------------------------------------------------------------------------
    # Listening
    # -------------------------------------------------------------------------
    def start(self, port: int) -> None:
        """Start the listening socket and accept thread."""
        if self.enc_dec_key is None or self.sign_key is None:
            raise RuntimeError("RSA keys must be loaded before starting the server.")
        if self._running:
            return

        self._listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listen_sock.bind(("0.0.0.0", port))
        self._listen_sock.listen(8)
        self._running = True
        self._listen_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._listen_thread.start()
        self.log_cb("server", f"Server listening on 0.0.0.0:{port}")

    def stop(self) -> None:
        """Stop accepting and disconnect every active client."""
        if not self._running:
            return
        self._running = False
        try:
            self._listen_sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self._listen_sock.close()
        except OSError:
            pass

        # Close every active connection so clients notice the server is down.
        # We shutdown(SHUT_RDWR) FIRST so any thread blocked in recv() on the
        # server side breaks out, AND the kernel sends a FIN to the client end.
        with self._conn_lock:
            users = list(self.active.items())
        for username, info in users:
            try:
                info["sock"].shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                info["sock"].close()
            except OSError:
                pass
        with self._conn_lock:
            self.active.clear()
        self.event_cb("active_changed", {})
        self.log_cb("server", "Server stopped. All client connections closed.")

    def _accept_loop(self) -> None:
        while self._running:
            try:
                client_sock, addr = self._listen_sock.accept()
            except OSError:
                # listening socket was closed
                break
            self.log_cb("server", f"Incoming connection from {addr[0]}:{addr[1]}")
            t = threading.Thread(
                target=self._client_thread, args=(client_sock, addr), daemon=True
            )
            t.start()

    # -------------------------------------------------------------------------
    # Per-connection handler
    # -------------------------------------------------------------------------
    def _client_thread(self, sock: socket.socket, addr) -> None:
        """
        Handle one client connection. The first message determines the flow:
            type == "ENROLL_REQ"    -> one-shot enrollment exchange
            type == "AUTH_REQ"      -> challenge-response then broadcast loop
        """
        username = None
        channel = None
        try:
            first = cu.recv_msg(sock)
            mtype = first.get("type")

            if mtype == "ENROLL_REQ":
                self._handle_enrollment(sock, first, addr)
                # Enrollment is one-shot: close after responding.
                return

            if mtype == "AUTH_REQ":
                login_result = self._handle_authentication(sock, first, addr)
                if login_result is None:
                    return
                username, channel = login_result
                # Now in broadcast phase.
                self._broadcast_loop(sock, username, channel)
                return

            self.log_cb("server", f"Unknown first message type from {addr}: {mtype}")
        except (ConnectionError, OSError, ValueError) as e:
            self.log_cb("server", f"Connection error with {addr}: {e}")
        finally:
            # Cleanup: if this was an authenticated session, drop it.
            if username is not None:
                with self._conn_lock:
                    if username in self.active and self.active[username]["sock"] is sock:
                        del self.active[username]
                self.event_cb("active_changed", {})
                self.log_cb(
                    "server",
                    f"Client '{username}' (channel {channel}) disconnected.",
                )
            try:
                sock.close()
            except OSError:
                pass

    # -------------------------------------------------------------------------
    # Enrollment handling
    # -------------------------------------------------------------------------
    def _handle_enrollment(self, sock: socket.socket, msg: dict, addr) -> None:
        """
        Decrypt the OAEP-encrypted enrollment payload, validate uniqueness,
        store the user, and send a signed success/error response.
        """
        try:
            ciphertext = cu.from_hex(msg["payload_hex"])
        except (KeyError, ValueError):
            self._send_signed_text(sock, "error: malformed enrollment request")
            return

        self.log_cb("server", f"[Enrollment] Received encrypted payload from {addr}")
        self.log_cb("server", f"  ciphertext: {cu.short_hex(ciphertext)}")

        try:
            plaintext = cu.rsa_decrypt(self.enc_dec_key, ciphertext)
        except ValueError as e:
            self.log_cb("server", f"[Enrollment] RSA decryption failed: {e}")
            self._send_signed_text(sock, "error: rsa decryption failed")
            return

        try:
            username, h_pw, h_rev_pw, channel = cu.decode_enrollment(plaintext)
        except ValueError as e:
            self.log_cb("server", f"[Enrollment] Could not parse decrypted payload: {e}")
            self._send_signed_text(sock, "error: malformed enrollment payload")
            return

        h_pw_hex = cu.to_hex(h_pw)
        h_rev_pw_hex = cu.to_hex(h_rev_pw)

        # Log the parsed enrollment data
        self.log_cb("server", "[Enrollment] Decrypted payload:")
        self.log_cb("server", f"  username: {username}")
        self.log_cb("server", f"  channel:  {channel}")
        self.log_cb("server", f"  h(pw):     {h_pw_hex}")
        self.log_cb("server", f"  h(rev_pw): {h_rev_pw_hex}")

        if not username or len(username) > 32:
            self._send_signed_text(sock, "error: invalid username")
            return
        if channel not in cu.CHANNELS:
            self._send_signed_text(sock, "error: invalid channel")
            return

        with self._db_lock:
            if username in self.enrollments:
                self.log_cb(
                    "server",
                    f"[Enrollment] Rejected: username '{username}' already taken.",
                )
                self._send_signed_text(sock, "error: username already taken")
                return

            self.enrollments[username] = {
                "h_pw_hex": h_pw_hex,
                "h_rev_pw_hex": h_rev_pw_hex,
                "channel": channel,
            }
            self._persist_db()

        self.log_cb(
            "server",
            f"[Enrollment] Successfully enrolled user '{username}' on channel {channel}.",
        )
        self._send_signed_text(
            sock, f"success: enrollment complete for '{username}' on {channel}"
        )

    def _send_signed_text(self, sock: socket.socket, text: str) -> None:
        """Send a plain text response with the server's RSA signature."""
        text_bytes = text.encode("utf-8")
        sig = cu.rsa_sign(self.sign_key, text_bytes)
        self.log_cb("server", f"[Enrollment] Sending signed response: '{text}'")
        self.log_cb("server", f"  signature: {cu.short_hex(sig)}")
        cu.send_msg(
            sock,
            {
                "type": "ENROLL_RESP",
                "message": text,
                "signature_hex": cu.to_hex(sig),
            },
        )

    # -------------------------------------------------------------------------
    # Authentication handling
    # -------------------------------------------------------------------------
    def _handle_authentication(self, sock: socket.socket, msg: dict, addr):
        """
        Perform the challenge-response protocol. Returns (username, channel) on
        success, else None.
        """
        username = msg.get("username", "").strip()
        self.log_cb("server", f"[Auth] Authentication request for username '{username}' from {addr}")

        # Find user record.
        with self._db_lock:
            user_record = self.enrollments.get(username)

        if user_record is None:
            # The spec says we should still go through the motions to avoid
            # leaking which usernames exist, but in practice for this project
            # we can return a clean failure. We choose to send a challenge,
            # then a generic "Authentication Unsuccessful" so the client has a
            # uniform protocol.
            self.log_cb("server", f"[Auth] No such user '{username}'. Will fail HMAC.")
            user_record = None

        # Step 1: server -> client : 128-bit random challenge (cleartext)
        challenge = cu.csprng_bytes(cu.NONCE_LEN)
        self.log_cb("server", f"[Auth] Generated 128-bit challenge: {cu.to_hex(challenge)}")
        cu.send_msg(sock, {"type": "AUTH_CHALLENGE", "challenge_hex": cu.to_hex(challenge)})

        # Step 2: client -> server : HMAC of challenge using lower 32 bytes of h(pw)
        resp = cu.recv_msg(sock)
        if resp.get("type") != "AUTH_HMAC":
            self.log_cb("server", "[Auth] Expected AUTH_HMAC, got something else. Aborting.")
            return None
        client_mac_hex = resp.get("hmac_hex", "")
        self.log_cb("server", f"[Auth] Received HMAC from client: {client_mac_hex}")

        # Step 3: verify HMAC
        ok = False
        if user_record is not None:
            h_pw = cu.from_hex(user_record["h_pw_hex"])
            hmac_key = cu.derive_hmac_key_from_hash(h_pw)
            expected = cu.hmac_sha3_512(hmac_key, challenge)
            self.log_cb("server", f"[Auth] Expected HMAC:        {cu.to_hex(expected)}")
            try:
                ok = cu.hmac_verify(hmac_key, challenge, cu.from_hex(client_mac_hex))
            except ValueError:
                ok = False

        # Determine the AES key and IV used to encrypt the result. These come
        # from h(rev_pw), which we stored at enrollment.
        if user_record is not None:
            h_rev_pw = cu.from_hex(user_record["h_rev_pw_hex"])
            ack_aes_key, ack_iv = cu.derive_aes_key_iv_from_hash(h_rev_pw)
        else:
            # No user record: invent a placeholder so the wire protocol is
            # uniform. The client won't be able to decrypt it; that's fine.
            ack_aes_key = cu.csprng_bytes(cu.AES_KEY_LEN)
            ack_iv = cu.csprng_bytes(cu.AES_BLOCK_SIZE)

        # Step 4a: HMAC failed -> encrypted+signed "Authentication Unsuccessful"
        if not ok:
            self.log_cb("server", "[Auth] HMAC verification FAILED.")
            ct = cu.aes_encrypt(ack_aes_key, ack_iv, cu.AUTH_FAIL_TEXT)
            sig = cu.rsa_sign(self.sign_key, ct)
            self.log_cb("server", f"[Auth] Encrypted negative ack: {cu.short_hex(ct)}")
            self.log_cb("server", f"[Auth] Signature:              {cu.short_hex(sig)}")
            cu.send_msg(
                sock,
                {
                    "type": "AUTH_RESULT",
                    "ciphertext_hex": cu.to_hex(ct),
                    "signature_hex": cu.to_hex(sig),
                },
            )
            return None

        # Step 4b: HMAC OK. Now check that channel keys exist.
        self.log_cb("server", f"[Auth] HMAC verified OK for user '{username}'.")
        channel = user_record["channel"]

        with self._channel_lock:
            ckeys = self.channel_keys.get(channel)

        if ckeys is None:
            self.log_cb(
                "server",
                f"[Auth] Channel '{channel}' has no keys yet. Sending 'Channel Unavailable'.",
            )
            ct = cu.aes_encrypt(ack_aes_key, ack_iv, cu.AUTH_CHANNEL_UNAVAILABLE)
            sig = cu.rsa_sign(self.sign_key, ct)
            cu.send_msg(
                sock,
                {
                    "type": "AUTH_RESULT",
                    "ciphertext_hex": cu.to_hex(ct),
                    "signature_hex": cu.to_hex(sig),
                },
            )
            return None

        # Refuse if user already has an active session.
        with self._conn_lock:
            if username in self.active:
                self.log_cb(
                    "server",
                    f"[Auth] User '{username}' is already connected from another session.",
                )
                ct = cu.aes_encrypt(ack_aes_key, ack_iv, cu.AUTH_FAIL_TEXT)
                sig = cu.rsa_sign(self.sign_key, ct)
                cu.send_msg(
                    sock,
                    {
                        "type": "AUTH_RESULT",
                        "ciphertext_hex": cu.to_hex(ct),
                        "signature_hex": cu.to_hex(sig),
                    },
                )
                return None
            self.active[username] = {"sock": sock, "channel": channel, "addr": (addr[0], addr[1])}
        self.event_cb("active_changed", {})

        # Build the success payload:
        #     "Authentication Successful" || aes_key (32) || iv (16) ||
        #     hmac_key (32) || channel_name_bytes
        # The channel name lets the client display it without storing
        # anything locally besides the password input.
        payload = (
            cu.AUTH_OK_TEXT
            + ckeys["aes_key"]
            + ckeys["iv"]
            + ckeys["hmac_key"]
            + channel.encode("utf-8")
        )
        ct = cu.aes_encrypt(ack_aes_key, ack_iv, payload)
        sig = cu.rsa_sign(self.sign_key, ct)
        self.log_cb("server", f"[Auth] Encrypted positive ack (with channel keys): {cu.short_hex(ct)}")
        self.log_cb("server", f"[Auth] Signature: {cu.short_hex(sig)}")

        cu.send_msg(
            sock,
            {
                "type": "AUTH_RESULT",
                "ciphertext_hex": cu.to_hex(ct),
                "signature_hex": cu.to_hex(sig),
            },
        )
        self.log_cb(
            "server",
            f"[Auth] User '{username}' authenticated to channel {channel}.",
        )
        return username, channel

    # -------------------------------------------------------------------------
    # Broadcast loop (server only relays; never decrypts/verifies)
    # -------------------------------------------------------------------------
    def _broadcast_loop(self, sock: socket.socket, username: str, channel: str) -> None:
        while True:
            try:
                msg = cu.recv_msg(sock)
            except (ConnectionError, OSError, ValueError):
                return

            mtype = msg.get("type")
            if mtype == "BROADCAST":
                ct_hex = msg.get("ciphertext_hex", "")
                mac_hex = msg.get("hmac_hex", "")
                self.log_cb(
                    channel,
                    f"<- '{username}' broadcast | ct={cu.short_hex(cu.from_hex(ct_hex)) if ct_hex else ''}"
                    f" | hmac={cu.short_hex(cu.from_hex(mac_hex)) if mac_hex else ''}",
                )
                self._relay(channel, username, ct_hex, mac_hex)
            elif mtype == "DISCONNECT":
                self.log_cb("server", f"User '{username}' requested disconnect.")
                return
            else:
                self.log_cb("server", f"Unknown message type from '{username}': {mtype}")

    def _relay(self, channel: str, sender: str, ciphertext_hex: str, hmac_hex: str) -> None:
        """Forward to every connected client subscribed to the same channel."""
        with self._conn_lock:
            recipients = [
                (uname, info["sock"])
                for uname, info in self.active.items()
                if info["channel"] == channel
            ]
        out = {
            "type": "BROADCAST",
            "from": sender,
            "channel": channel,
            "ciphertext_hex": ciphertext_hex,
            "hmac_hex": hmac_hex,
        }
        delivered = 0
        for uname, rsock in recipients:
            try:
                cu.send_msg(rsock, out)
                delivered += 1
            except (OSError, ConnectionError):
                pass
        self.log_cb(channel, f"-> Relayed message from '{sender}' to {delivered} subscriber(s).")

    # -------------------------------------------------------------------------
    # Inspection helpers
    # -------------------------------------------------------------------------
    def list_active(self):
        with self._conn_lock:
            return [
                (uname, info["channel"], info["addr"])
                for uname, info in self.active.items()
            ]

    def list_enrolled(self):
        with self._db_lock:
            return [(u, rec["channel"]) for u, rec in self.enrollments.items()]


# =============================================================================
# Tkinter GUI
# =============================================================================
class ServerGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("CS432 Project — Secure Channel Server")
        self.root.geometry("1100x780")

        # Bridge to dispatch worker-thread updates onto the Tk main thread.
        self._gui_q = queue.Queue()
        self.root.after(50, self._poll_gui_queue)

        # Channel-specific text widgets keyed by channel name; "server" -> master log.
        self._log_widgets = {}

        # The core protocol object
        self.core = SecureChannelServer(
            log_cb=self._log_threadsafe,
            event_cb=self._event_threadsafe,
        )

        # State for path entries
        self._enc_dec_path = tk.StringVar()
        self._sign_path = tk.StringVar()
        self._port_var = tk.StringVar(value="6000")

        # Per-channel master secret entry
        self._master_secrets = {ch: tk.StringVar() for ch in cu.CHANNELS}
        self._master_status = {ch: tk.StringVar(value="not generated") for ch in cu.CHANNELS}

        self._build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ------------------------------- UI layout -------------------------------
    def _build_ui(self):
        pad = {"padx": 6, "pady": 4}

        # --- Top: server setup ---
        setup = ttk.LabelFrame(self.root, text="Server Setup")
        setup.pack(fill=tk.X, **pad)

        ttk.Label(setup, text="Listening port:").grid(row=0, column=0, sticky="e", padx=4, pady=4)
        ttk.Entry(setup, textvariable=self._port_var, width=8).grid(row=0, column=1, sticky="w")

        ttk.Label(setup, text="Enc/Dec key (PEM):").grid(row=1, column=0, sticky="e", padx=4, pady=4)
        ttk.Entry(setup, textvariable=self._enc_dec_path, width=70).grid(row=1, column=1, columnspan=2, sticky="we")
        ttk.Button(setup, text="Browse", command=self._browse_enc_dec).grid(row=1, column=3, padx=4)

        ttk.Label(setup, text="Sign/Verify key (PEM):").grid(row=2, column=0, sticky="e", padx=4, pady=4)
        ttk.Entry(setup, textvariable=self._sign_path, width=70).grid(row=2, column=1, columnspan=2, sticky="we")
        ttk.Button(setup, text="Browse", command=self._browse_sign).grid(row=2, column=3, padx=4)

        btnbar = ttk.Frame(setup)
        btnbar.grid(row=3, column=0, columnspan=4, sticky="we", pady=4)
        self._start_btn = ttk.Button(btnbar, text="Start Server", command=self._on_start)
        self._start_btn.pack(side=tk.LEFT, padx=4)
        self._stop_btn = ttk.Button(btnbar, text="Stop Server", command=self._on_stop, state=tk.DISABLED)
        self._stop_btn.pack(side=tk.LEFT, padx=4)

        # --- Channel master secrets ---
        ms = ttk.LabelFrame(self.root, text="Per-Channel Master Secret  (keys are derived once and remain fixed)")
        ms.pack(fill=tk.X, **pad)

        for i, ch in enumerate(cu.CHANNELS):
            ttk.Label(ms, text=f"{ch}:", width=10).grid(row=i, column=0, sticky="e", padx=4, pady=2)
            ttk.Entry(ms, textvariable=self._master_secrets[ch], width=40, show="*").grid(row=i, column=1, sticky="we")
            ttk.Button(ms, text="Generate Keys", command=lambda c=ch: self._on_generate(c)).grid(row=i, column=2, padx=4)
            ttk.Label(ms, textvariable=self._master_status[ch], foreground="#444", width=20).grid(row=i, column=3, sticky="w")

        # --- Active clients ---
        active = ttk.LabelFrame(self.root, text="Online clients")
        active.pack(fill=tk.X, **pad)
        self._active_list = tk.Listbox(active, height=4)
        self._active_list.pack(fill=tk.X, padx=4, pady=4)

        # --- Logs notebook ---
        nb = ttk.Notebook(self.root)
        nb.pack(fill=tk.BOTH, expand=True, **pad)

        # One tab per channel (shows messages / relays for that channel)
        for ch in cu.CHANNELS:
            frame = ttk.Frame(nb)
            txt = tk.Text(frame, wrap=tk.WORD, height=18)
            scr = ttk.Scrollbar(frame, command=txt.yview)
            txt.configure(yscrollcommand=scr.set)
            txt.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            scr.pack(side=tk.RIGHT, fill=tk.Y)
            nb.add(frame, text=f"Channel {ch}")
            self._log_widgets[ch] = txt

        # The server-wide log (RSA keys, enrollment, auth flow, errors)
        frame_s = ttk.Frame(nb)
        txt_s = tk.Text(frame_s, wrap=tk.WORD, height=18)
        scr_s = ttk.Scrollbar(frame_s, command=txt_s.yview)
        txt_s.configure(yscrollcommand=scr_s.set)
        txt_s.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scr_s.pack(side=tk.RIGHT, fill=tk.Y)
        nb.add(frame_s, text="Server Log")
        self._log_widgets["server"] = txt_s

    # ------------------------------ Callbacks --------------------------------
    def _browse_enc_dec(self):
        p = filedialog.askopenfilename(
            title="Select Enc/Dec PEM (private+public)",
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")],
        )
        if p:
            self._enc_dec_path.set(p)

    def _browse_sign(self):
        p = filedialog.askopenfilename(
            title="Select Sign/Verify PEM (private+public)",
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")],
        )
        if p:
            self._sign_path.set(p)

    def _on_start(self):
        try:
            port = int(self._port_var.get())
            if not (1 <= port <= 65535):
                raise ValueError("port out of range")
        except ValueError:
            messagebox.showerror("Bad port", "Please enter a valid port number (1-65535).")
            return

        if not self._enc_dec_path.get() or not self._sign_path.get():
            messagebox.showerror("Missing keys", "Please select both PEM key files.")
            return

        try:
            self.core.load_rsa_keys(self._enc_dec_path.get(), self._sign_path.get())
            self.core.start(port)
        except (OSError, ValueError, RuntimeError) as e:
            messagebox.showerror("Cannot start server", str(e))
            return

        self._start_btn.configure(state=tk.DISABLED)
        self._stop_btn.configure(state=tk.NORMAL)

    def _on_stop(self):
        self.core.stop()
        self._start_btn.configure(state=tk.NORMAL)
        self._stop_btn.configure(state=tk.DISABLED)

    def _on_generate(self, channel: str):
        secret = self._master_secrets[channel].get()
        if not secret:
            messagebox.showerror("Empty master secret", f"Enter a master secret for {channel}.")
            return
        try:
            self.core.generate_channel_keys(channel, secret)
            self._master_status[channel].set("READY")
        except (ValueError, RuntimeError) as e:
            messagebox.showerror("Channel keygen", str(e))

    def _on_close(self):
        try:
            self.core.stop()
        except Exception:
            pass
        self.root.destroy()

    # --------------------- Thread-safe GUI update plumbing -------------------
    def _log_threadsafe(self, target: str, message: str):
        # Posted from worker threads; runs on Tk main thread when polled.
        self._gui_q.put(("log", target, message))

    def _event_threadsafe(self, name: str, payload: dict):
        self._gui_q.put(("event", name, payload))

    def _poll_gui_queue(self):
        try:
            while True:
                kind, *rest = self._gui_q.get_nowait()
                if kind == "log":
                    target, message = rest
                    widget = self._log_widgets.get(target, self._log_widgets["server"])
                    widget.insert(tk.END, message + "\n")
                    widget.see(tk.END)
                elif kind == "event":
                    name, _payload = rest
                    if name == "active_changed":
                        self._refresh_active()
        except queue.Empty:
            pass
        self.root.after(50, self._poll_gui_queue)

    def _refresh_active(self):
        self._active_list.delete(0, tk.END)
        for uname, ch, addr in self.core.list_active():
            self._active_list.insert(tk.END, f"{uname}  ({ch})  from {addr[0]}:{addr[1]}")

    # --------------------------------- run -----------------------------------
    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    ServerGUI().run()