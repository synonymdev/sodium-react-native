/* eslint-disable no-bitwise */

export function mapArgs(arg: number | Uint8Array | null) {
  if (arg === null) return [];
  if (typeof arg === 'number') return arg;
  return Array.from(arg);
}

// constant time compare
export function vn(
  x: Uint8Array,
  xi: number,
  y: Uint8Array,
  yi: number,
  n: number
) {
  let d = 0;
  for (let i = 0; i < n; i++) d |= x[xi + i] ^ y[yi + i];
  return (1 & ((d - 1) >>> 8)) - 1;
}
