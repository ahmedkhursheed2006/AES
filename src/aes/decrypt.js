// AES-128 decryption implementation (single-block) using the inverse round functions
import { bytesToState, stateToBytes } from './utils.js';
import { expandKey } from './keySchedule.js';
import { invSubBytes, invShiftRows, invMixColumns, addRoundKey } from './rounds.js';

// Decrypt a single 16-byte block. onRound is an optional callback receiving (roundNumber, stateBytes)
// Round numbering mirrors the encrypt callback: 0 = after initial AddRoundKey (with last round key),
// 1..9 = after each inverse round, 10 = after final AddRoundKey (original round key 0)
export function decryptBlock(cipherBlock, keyBytes, onRound) {
  const state = bytesToState(cipherBlock);
  const roundKeys = expandKey(keyBytes);
  const Nr = roundKeys.length - 1; // 14 for AES-256

  // Initial AddRoundKey with round key Nr
  addRoundKey(state, roundKeys[Nr]);
  if (onRound) onRound(0, stateToBytes(state));

  // Nr-1 down to 1 inverse rounds
  let dr = 1; // decryption round counter for logging
  for (let round = Nr - 1; round >= 1; round--) {
    invShiftRows(state);
    invSubBytes(state);
    addRoundKey(state, roundKeys[round]);
    invMixColumns(state);
    if (onRound) onRound(dr, stateToBytes(state));
    dr++;
  }

  // Final inverse round (no invMixColumns)
  invShiftRows(state);
  invSubBytes(state);
  addRoundKey(state, roundKeys[0]);
  if (onRound) onRound(Nr, stateToBytes(state));

  return stateToBytes(state);
}

export function decryptBlockHex(ciphertextHex, keyHex, onRound) {
  // convenience wrapper: hex inputs -> hex output
  const hexToBytes = (hex) => {
    const clean = hex.replace(/[^0-9a-fA-F]/g, '');
    if (clean.length % 2 !== 0) throw new Error('Invalid hex string');
    const out = new Uint8Array(clean.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i*2, 2), 16);
    return out;
  };

  const ct = hexToBytes(ciphertextHex);
  const key = hexToBytes(keyHex);
  const pt = decryptBlock(ct, key, onRound);

  // convert to hex
  return Array.from(pt).map(b => b.toString(16).padStart(2, '0')).join('');
}

export default {
  decryptBlock,
  decryptBlockHex,
};