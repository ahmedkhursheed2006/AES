// Utility helpers for AES operations: state conversion, GF(2^8) math, and conversions
import { SBOX, INV_SBOX } from './constants.js';

// Convert a 16-byte array into AES state (column-major order).
// AES state is a 4x4 byte matrix; we represent it as Uint8Array length 16.
export function bytesToState(bytes) {
  if (bytes.length !== 16) throw new Error('Block must be 16 bytes');
  return new Uint8Array(bytes); // we use flat 16-byte arrays; indexing convention: c*4 + r
}

// Convert state back to bytes
export function stateToBytes(state) {
  return new Uint8Array(state);
}

// XOR two byte arrays of same length
export function xorBytes(a, b) {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}

// xtime: multiply by x (i.e., 0x02) in GF(2^8)
export function xtime(byte) {
  return ((byte << 1) & 0xff) ^ ((byte & 0x80) ? 0x1b : 0x00);
}

// Multiply two bytes in GF(2^8) using Russian peasant multiplication
export function gfMul(a, b) {
  let res = 0;
  let aa = a;
  let bb = b;
  while (bb > 0) {
    if (bb & 1) res ^= aa;
    aa = xtime(aa);
    bb >>= 1;
  }
  return res & 0xff;
}

// Simple helper to convert a byte array to a hex string for readable logs
export function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Convert hex string to bytes (accepts even-length hex)
export function hexToBytes(hex) {
  const clean = hex.replace(/[^0-9a-fA-F]/g, '');
  if (clean.length % 2 !== 0) throw new Error('Invalid hex string');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i*2, 2), 16);
  return out;
}

// Convert UTF-8 string to byte block of specific length (pad with zeros if necessary)
export function stringToBlock(str, len = 16) {
  const encoder = new TextEncoder();
  const bytes = encoder.encode(str);
  const block = new Uint8Array(len);
  block.set(bytes.subarray(0, len)); // truncate or pad with zeros
  return block;
}

// Convert block to UTF-8 string (trim trailing zeros)
export function blockToString(block) {
  const trimmed = block.slice();
  // remove trailing zeros
  let end = trimmed.length;
  while (end > 0 && trimmed[end-1] === 0) end--; 
  return new TextDecoder().decode(trimmed.subarray(0, end));
}

// Apply S-box substitution to a single byte
export function subByte(b) {
  return SBOX[b];
}

// Apply inverse S-box substitution to a single byte (used during decryption)
export function invSubByte(b) {
  return INV_SBOX[b];
}
