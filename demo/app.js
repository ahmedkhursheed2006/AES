// Demo script that uses the modular AES implementation to encrypt and log after every round
import { stringToBlock, bytesToHex, blockToString, hexToBytes } from '../src/aes/utils.js';
import { expandKey } from '../src/aes/keySchedule.js';
import { encryptBlock } from '../src/aes/encrypt.js';
import { decryptBlock } from '../src/aes/decrypt.js';

const plaintextInput = document.getElementById('plaintext');
const keyInput = document.getElementById('key');
const encryptBtn = document.getElementById('encryptBtn');
const decryptBtn = document.getElementById('decryptBtn');
const ciphertextInput = document.getElementById('ciphertext');
const logDiv = document.getElementById('log');

function appendLog(msg) {
  console.log(msg);
  logDiv.textContent += msg + '\n';
}

encryptBtn.addEventListener('click', () => {
  console.clear();
  logDiv.textContent = '';
  // Prepare plaintext (16 bytes) and key (32 bytes for AES-256)
  const pBlock = stringToBlock(plaintextInput.value);
  const kBlock = stringToBlock(keyInput.value, 32);

  appendLog('Plaintext (UTF8) trimmed/padded to 16 bytes: ' + blockToString(pBlock));
  appendLog('Plaintext (hex): ' + bytesToHex(pBlock));
  appendLog('Key (hex): ' + bytesToHex(kBlock));

  // Optional: show round keys for debugging
  try {
    const rks = expandKey(kBlock);
    appendLog(`--- Round keys (0..${rks.length - 1}) ---`);
    rks.forEach((rk, idx) => appendLog('RoundKey['+idx+']: ' + bytesToHex(rk)));
    appendLog('--------------------------');
  } catch (e) {
    appendLog('Key expansion error: ' + e.message);
    return;
  }

  // Define a callback to receive state after each round
  function onRound(roundNumber, stateBytes) {
    appendLog(`[Round ${roundNumber}] state: ${bytesToHex(stateBytes)}`);
  }

  // Perform encryption and log after each round
  const cipher = encryptBlock(pBlock, kBlock, onRound);

  appendLog('Ciphertext (hex): ' + bytesToHex(cipher));
  appendLog('Encryption finished ✅');
});

// Decrypt handler
decryptBtn.addEventListener('click', () => {
  console.clear();
  logDiv.textContent = '';
  const cHex = ciphertextInput.value.trim();
  if (!cHex) { appendLog('Please input ciphertext hex'); return; }
  try {
    const cBytes = hexToBytes(cHex);
    if (cBytes.length !== 16) { appendLog('Ciphertext must be 16 bytes (32 hex chars)'); return; }

    const kBlock = stringToBlock(keyInput.value, 32);
    appendLog('Ciphertext (hex): ' + bytesToHex(cBytes));
    appendLog('Key (hex): ' + bytesToHex(kBlock));

    // onRound callback logs state after each decryption round
    function onRound(roundNumber, stateBytes) {
      appendLog(`[Round ${roundNumber}] state: ${bytesToHex(stateBytes)}`);
    }

    const plain = decryptBlock(cBytes, kBlock, onRound);
    appendLog('Plaintext (hex): ' + bytesToHex(plain));
    appendLog('Plaintext (utf8): ' + blockToString(plain));
    appendLog('Decryption finished ✅');
  } catch (e) {
    appendLog('Decrypt error: ' + e.message);
  }
});
