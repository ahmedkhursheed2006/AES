// AES round transformations: SubBytes, ShiftRows, MixColumns, AddRoundKey (and inverses)
import { subByte, invSubByte } from './utils.js';
import { gfMul } from './utils.js';

// SubBytes: apply S-box to every byte in the state
export function subBytes(state) {
  for (let i = 0; i < 16; i++) state[i] = subByte(state[i]);
}

// ShiftRows: left rotate rows by their row index
// Our state is column-major: index = c*4 + r
export function shiftRows(state) {
  // copy
  const s = new Uint8Array(state);
  // row 1 rotate left by 1
  state[1]  = s[5]; state[5]  = s[9]; state[9]  = s[13]; state[13] = s[1];
  // row 2 rotate left by 2
  state[2]  = s[10]; state[6]  = s[14]; state[10] = s[2];  state[14] = s[6];
  // row 3 rotate left by 3 (or right by 1)
  state[3]  = s[15]; state[7]  = s[3];  state[11] = s[7];  state[15] = s[11];
}

// MixColumns: mix each column using fixed polynomial multiplication
export function mixColumns(state) {
  for (let c = 0; c < 4; c++) {
    const i = c*4;
    const a0 = state[i+0];
    const a1 = state[i+1];
    const a2 = state[i+2];
    const a3 = state[i+3];

    // perform matrix multiplication in GF(2^8)
    state[i+0] = (gfMul(a0,2) ^ gfMul(a1,3) ^ a2 ^ a3) & 0xff;
    state[i+1] = (a0 ^ gfMul(a1,2) ^ gfMul(a2,3) ^ a3) & 0xff;
    state[i+2] = (a0 ^ a1 ^ gfMul(a2,2) ^ gfMul(a3,3)) & 0xff;
    state[i+3] = (gfMul(a0,3) ^ a1 ^ a2 ^ gfMul(a3,2)) & 0xff;
  }
}

// AddRoundKey: XOR state with round key (16 bytes)
export function addRoundKey(state, roundKey) {
  for (let i = 0; i < 16; i++) state[i] ^= roundKey[i];
}

// InvSubBytes: apply inverse S-box to every byte in the state
export function invSubBytes(state) {
  for (let i = 0; i < 16; i++) state[i] = invSubByte(state[i]);
}

// InvShiftRows: right rotate rows by their row index (inverse of ShiftRows)
export function invShiftRows(state) {
  const s = new Uint8Array(state);
  // row 1 rotate right by 1
  state[1]  = s[13]; state[5]  = s[1]; state[9]  = s[5]; state[13] = s[9];
  // row 2 rotate right by 2 (same as left by 2)
  state[2]  = s[10]; state[6]  = s[14]; state[10] = s[2];  state[14] = s[6];
  // row 3 rotate right by 3 (or left by 1)
  state[3]  = s[7]; state[7]  = s[11]; state[11] = s[15]; state[15] = s[3];
}

// InvMixColumns: inverse mix columns using GF(2^8) multipliers [0x0e,0x0b,0x0d,0x09]
export function invMixColumns(state) {
  for (let c = 0; c < 4; c++) {
    const i = c*4;
    const a0 = state[i+0];
    const a1 = state[i+1];
    const a2 = state[i+2];
    const a3 = state[i+3];

    state[i+0] = (gfMul(a0,0x0e) ^ gfMul(a1,0x0b) ^ gfMul(a2,0x0d) ^ gfMul(a3,0x09)) & 0xff;
    state[i+1] = (gfMul(a0,0x09) ^ gfMul(a1,0x0e) ^ gfMul(a2,0x0b) ^ gfMul(a3,0x0d)) & 0xff;
    state[i+2] = (gfMul(a0,0x0d) ^ gfMul(a1,0x09) ^ gfMul(a2,0x0e) ^ gfMul(a3,0x0b)) & 0xff;
    state[i+3] = (gfMul(a0,0x0b) ^ gfMul(a1,0x0d) ^ gfMul(a2,0x09) ^ gfMul(a3,0x0e)) & 0xff;
  }
}
