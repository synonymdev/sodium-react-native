import { vn } from './helpers';

export function crypto_verify_16(
  x: Uint8Array,
  xi: number,
  y: Uint8Array,
  yi: number
) {
  return vn(x, xi, y, yi, 16) === 0;
}

export function crypto_verify_32(
  x: Uint8Array,
  xi: number,
  y: Uint8Array,
  yi: number
) {
  return vn(x, xi, y, yi, 32) === 0;
}

export function crypto_verify_64(
  x: Uint8Array,
  xi: number,
  y: Uint8Array,
  yi: number
) {
  return vn(x, xi, y, yi, 64) === 0;
}
