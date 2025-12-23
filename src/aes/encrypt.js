// High-level AES-128 encrypt function that uses the modular pieces
import { bytesToState, stateToBytes, bytesToHex, hexToBytes } from './utils.js';
import { expandKey } from './keySchedule.js';
import { subBytes, shiftRows, mixColumns, addRoundKey } from './rounds.js';

// Encrypt a single 16-byte block. onRound is an optional callback receiving (roundNumber, stateBytes)
// Round numbering: 0 = after initial AddRoundKey, 1..9 after each full round, 10 after final round
export function encryptBlock(plaintextBlock, keyBytes, onRound) {
  const state = bytesToState(plaintextBlock);
  const roundKeys = expandKey(keyBytes);
  const Nr = roundKeys.length - 1; // 14 for AES-256

  // Initial AddRoundKey (round 0)
  addRoundKey(state, roundKeys[0]);
  if (onRound) onRound(0, stateToBytes(state));

  // Rounds 1 to Nr-1
  for (let round = 1; round < Nr; round++) {
    subBytes(state);
    shiftRows(state);
    mixColumns(state);
    addRoundKey(state, roundKeys[round]);
    if (onRound) onRound(round, stateToBytes(state));
  }

  // final round (no mixColumns)
  subBytes(state);
  shiftRows(state);
  addRoundKey(state, roundKeys[Nr]);
  if (onRound) onRound(Nr, stateToBytes(state));

  return stateToBytes(state);
}

// Convenience function: accepts hex strings for plaintext and key and returns ciphertext hex
export function encryptBlockHex(plaintextHex, keyHex, onRound) {
  const plainBytes = hexToBytes(plaintextHex);
  const keyBytes = hexToBytes(keyHex);
  const cipher = encryptBlock(plainBytes, keyBytes, onRound);
  return bytesToHex(cipher);
}

// Exports:
export default {
  encryptBlock,
  encryptBlockHex,
};
