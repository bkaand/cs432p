# CS432 Project — Secure Channel Broadcast Application

A client-server application for secure and authenticated message broadcast among subscribers of three channels (`IF100`, `MATH101`, `SPS101`). Implements enrollment, challenge-response authentication, and AES-CBC + HMAC-SHA3-512 broadcast as specified in the project document.

## Files

- `server.py` - Server module with tkinter GUI (network code + GUI in one file).
- `client.py` - Client module with tkinter GUI.
- `crypto_utils.py` - Shared crypto primitives and wire-protocol helpers (used by both server and client).
- `requirements.txt` - The single Python dependency (`pycryptodome`).

## Required PEM key files

You need the four key files from the project pack:

- `server_enc_dec_pub.pem` (client side, for RSA encryption to server)
- `server_sign_verify_pub.pem` (client side, for verifying server signatures)
- `server_enc_dec_pub_prv.pem` (server side, full keypair for RSA-OAEP decryption)
- `server_sign_verify_prv.pem` (server side, full keypair for signing)

The PEM files are loaded from the file system at runtime via "Browse" buttons on the GUIs (so you can place them anywhere).

## Setup

```bash
pip install -r requirements.txt
```

Python 3.9+ is fine. On Linux you may also need `python3-tk` from your package manager (macOS and Windows ship with tkinter built in, so you don't need to do anything there).

## Running

Open two terminals.

**Terminal 1 — Server:**

```bash
python3 server.py
```

In the server GUI:

1. Enter a port (e.g. `5050`).
2. Click "Browse..." next to **Encryption / Decryption Keypair** and select `server_enc_dec_pub_prv.pem`.
3. Click "Browse..." next to **Signing / Verification Keypair** and select `server_sign_verify_prv.pem`.
4. Click **Start Server**. The server log tab shows the loaded RSA modulus, public exponent, and listening status.
5. For each channel you want to enable, type any master secret and click **Generate Keys**. The derived AES key, IV and HMAC key are shown in hex on that channel's tab. Note: once generated, master secrets are locked for the server's lifetime (per the spec).

**Terminal 2 — Client:**

```bash
python3 client.py
```

In the client GUI:

1. Click "Browse..." next to **Server Encryption Public Key** and select `server_enc_dec_pub.pem`.
2. Click "Browse..." next to **Server Signature Public Key** and select `server_sign_verify_pub.pem`.
3. Enter the server IP (`127.0.0.1` for local testing) and the same port the server is using.
4. **Enroll** — pick a username, password, and channel, then click **Enroll**. The crypto log shows the RSA-encrypted enrollment payload, signed response from the server, and verification result.
5. **Login** — enter the same username and password and click **Login**. On success the channel name appears in the status bar and the channel tab becomes active.
6. **Send messages** — type in the input field and press Enter (or click Send). The encrypted ciphertext, HMAC, and plaintext (after server echo) are shown on the channel tab.

To demo the broadcast, open a second `python3 client.py` instance, enroll a different user on the same channel, log in, and verify both clients see each other's messages.

## What the GUIs display (golden-rule coverage)

The spec's golden rule is "if we cannot follow what is going on, we cannot grade." Both GUIs show, in hex where applicable:

- **Server**: RSA modulus and public exponent of both loaded keypairs; decrypted enrollment payloads (username, h(pw), h(rev pw), channel); challenge nonces sent for each auth request; HMAC verification results (success/failure); signatures over auth-result ciphertexts; channel master secrets, AES keys, IVs, HMAC keys; list of currently connected authenticated users with their channels; relayed broadcast packets (ciphertext + HMAC) per channel.
- **Client**: server public-key fingerprints; encrypted enrollment payload; signed enrollment-response signature and verification result; sent challenge response (HMAC); decrypted auth-result plaintext including received channel keys/IV; outgoing AES ciphertext and HMAC for each broadcast; incoming ciphertext, HMAC verification result, and decrypted plaintext.

## Cryptographic specification

- **Hash**: SHA3-512 everywhere (passwords, RSA-OAEP, RSA signatures, HMAC).
- **RSA**: 3072-bit. Encryption uses OAEP with SHA3-512. Signatures use PKCS1v1.5 with SHA3-512.
- **Enrollment payload (RSA-encrypted)**: Compact binary format `[1B ulen][username][64B h_pw][64B h_rev_pw][1B clen][channel]`. JSON-with-hex would have exceeded the OAEP ciphertext capacity (254 bytes for RSA-3072 + SHA3-512), so a binary layout is used; both sides serialize/parse this in `crypto_utils.encode_enrollment` / `decode_enrollment`.
- **Auth challenge**: 128-bit cryptographically secure random number (CSPRNG via `Crypto.Random.get_random_bytes`).
- **Auth response**: HMAC-SHA3-512(challenge) keyed with `SHA3-512(password)[0:32]`.
- **Auth-result encryption**: AES-256-CBC with `key = SHA3-512(rev_pw)[0:32]`, `iv = SHA3-512(rev_pw)[32:48]`. Ciphertext is then RSA-signed.
- **Auth-result plaintext on success**: `"Authentication Successful" || aes_key(32) || iv(16) || hmac_key(32) || channel_name`. The channel name is appended at the end so the client can display it (since clients don't store passwords or channel choices locally).
- **Channel keys**: From master secret M, with `H = SHA3-512(M)`: `aes_key = H[0:32]`, `iv = H[32:48]`, last 16 bytes discarded. `hmac_key = SHA3-512(reverse(M))[0:32]`.
- **Broadcast packet**: client AES-CBC encrypts the message, computes HMAC-SHA3-512 over the ciphertext with the channel HMAC key, sends both. The server relays unchanged to all other clients on the same channel (and echoes back to the sender). Receivers verify HMAC, then decrypt.

## Wire format

All messages are length-prefixed JSON: `[4-byte big-endian length][UTF-8 JSON]`. Binary fields are hex-encoded inside the JSON. The single exception is the inner enrollment payload which is binary inside an RSA ciphertext (because hex+JSON exceeded OAEP's plaintext capacity, as noted above).

## Persistence

Enrollments are stored in `server_enrollments.json` in the server's working directory. Channel keys are NOT persisted — they are regenerated only via the GUI master-secret entry and live only in the server process's memory, as the spec requires.

## Edge cases handled

- Wrong password during login → AES decryption fails, client shows an error and lets the user retry.
- Channel keys not yet generated when a user logs in → server returns an AES-encrypted `"Channel Unavailable"` message; client shows it and offers retry.
- Tampered broadcast ciphertext or HMAC → receiver's HMAC verification fails, message discarded with a notice in the GUI; sender and other receivers are unaffected.
- Duplicate username at enrollment → server returns a signed error.
- Same username trying to log in twice concurrently → server refuses the second session.
- Client closes the window or disconnects → server cleans up the user's online session; the same user can later log in again with a fresh authentication.
- Server closes (disconnect button or window close) → server calls `shutdown(SHUT_RDWR)` on every active socket, which wakes blocked client `recv()` calls; clients display "Server disconnected" and clean up.
- Neither side crashes on disconnects — all socket and thread teardown is wrapped in try/except.

## Tested

A headless end-to-end test (`test_e2e.py`, included in the development directory but not strictly required for grading) exercises 14 scenarios: enrollment success, duplicate-username rejection, login-before-keys ("Channel Unavailable"), key generation and regeneration-rejection, successful login, wrong-password handling, broadcast (with self-echo), cross-channel isolation, tampered-HMAC rejection, single-client disconnect cleanup, and server-stop propagation to all clients. All scenarios pass.
