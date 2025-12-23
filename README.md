# AES-256 (from-scratch) — Demo

This small project implements AES-256 encryption from scratch in JavaScript and demonstrates it in the browser.

Files:
- `src/aes/constants.js` — S-Box and Rcon constants.
- `src/aes/utils.js` — Byte and state helpers, GF(2^8) math, conversions.
- `src/aes/keySchedule.js` — AES-256 key expansion.
- `src/aes/rounds.js` — SubBytes, ShiftRows, MixColumns, AddRoundKey.
- `src/aes/encrypt.js` — High-level `encryptBlock` that logs after each round.
- `src/aes/decrypt.js` — Decryption routines (inverse transforms) and `decryptBlock`.
- `demo/index.html` & `demo/app.js` — Browser demo: encrypts/decrypts one 16-byte block and logs state after every round.

How to run:
1. Open `demo/index.html` in a modern browser that supports ES modules.
2. Enter plaintext and key (they will be truncated/padded to 16 bytes) and click Encrypt.
3. See per-round logs in the page and in the console.

Notes:
- This implementation is educational and intended for learning; it's not audited for production use.
- Only AES-256 is implemented (32-byte key; 14 rounds).
