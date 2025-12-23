// AES-128 key expansion (key schedule) implementation
import { SBOX, RCON } from './constants.js';

// Rotate a 4-byte word left by one byte
function rotWord(word) {
  return Uint8Array.of(word[1], word[2], word[3], word[0]);
}

// Apply S-box to each byte of a 4-byte word
function subWord(word) {
  return Uint8Array.of(SBOX[word[0]], SBOX[word[1]], SBOX[word[2]], SBOX[word[3]]);
}

// Expand a 32-byte AES-256 key into 15 round keys (15 * 16 = 240 bytes)
export function expandKey(keyBytes) {
  if (keyBytes.length !== 32) throw new Error('Only AES-256(32-byte key) is supported by this implementation');
  const Nk = 8; // words in key (AES-256)
  const Nr = 14; // rounds (AES-256)
  const Nb = 4; // words in block
  const w = new Uint8Array(4 * Nb * (Nr + 1)); // 240 bytes
  // copy original key
  w.set(keyBytes);

  const temp = new Uint8Array(4);
  let i = Nk;
  while (i < Nb * (Nr + 1)) {
    temp[0] = w[4*(i-1) + 0];
    temp[1] = w[4*(i-1) + 1];
    temp[2] = w[4*(i-1) + 2];
    temp[3] = w[4*(i-1) + 3];

    if (i % Nk === 0) {
      // RotWord
      const rotated = rotWord(temp);
      // SubWord
      const subbed = subWord(rotated);
      // XOR with Rcon
      subbed[0] ^= RCON[i / Nk];
      temp.set(subbed);
    } else if (Nk > 6 && i % Nk === 4) {
      // AES-256 specific: SubWord only for the 4th word in the cycle
      const subbed = subWord(temp);
      temp.set(subbed);
    }

    // w[i] = w[i - Nk] ^ temp
    w[4*i + 0] = w[4*(i - Nk) + 0] ^ temp[0];
    w[4*i + 1] = w[4*(i - Nk) + 1] ^ temp[1];
    w[4*i + 2] = w[4*(i - Nk) + 2] ^ temp[2];
    w[4*i + 3] = w[4*(i - Nk) + 3] ^ temp[3];

    i++;
  }

  // Return array of 11 round keys, each 16 bytes
  const roundKeys = [];
  for (let r = 0; r <= Nr; r++) {
    roundKeys.push(w.slice(16*r, 16*(r+1)));
  }
  return roundKeys;
}
