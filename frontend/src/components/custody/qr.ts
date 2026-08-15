// Minimal, dependency-free QR Code generator (byte mode, EC level L/M/Q/H).
// Vendored so the Custody deposit screen can render a scannable QR without
// adding an npm dependency. Compact TS implementation of the QR standard
// (Reed–Solomon + mask + format info). Supports versions 1–10, which covers
// crypto addresses comfortably. Returns a boolean module matrix (true = dark).
//
// Written to be clean under noUncheckedIndexedAccess: hot lookup tables are
// Uint8Array-indexed (which yield `number`, not `number | undefined`), and
// small config tuples are read via helpers that assert presence.

type ECLevel = "L" | "M" | "Q" | "H";

// GF(256) tables for Reed–Solomon.
const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);
(function initGF() {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x;
    LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255]!;
})();

function gfMul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return EXP[LOG[a]! + LOG[b]!]!;
}

function rsGenPoly(degree: number): Uint8Array {
  let poly = new Uint8Array([1]);
  for (let i = 0; i < degree; i++) {
    const next = new Uint8Array(poly.length + 1);
    for (let j = 0; j < poly.length; j++) {
      next[j] = next[j]! ^ poly[j]!;
      next[j + 1] = next[j + 1]! ^ gfMul(poly[j]!, EXP[i]!);
    }
    poly = next;
  }
  return poly;
}

function rsEncode(data: number[], ecCount: number): number[] {
  const gen = rsGenPoly(ecCount);
  const res = new Uint8Array(ecCount);
  for (const d of data) {
    const factor = d ^ res[0]!;
    for (let i = 0; i < res.length - 1; i++) res[i] = res[i + 1]!;
    res[res.length - 1] = 0;
    for (let i = 0; i < gen.length - 1; i++) {
      res[i] = res[i]! ^ gfMul(gen[i + 1]!, factor);
    }
  }
  return Array.from(res);
}

// EC + capacity tables for versions 1..10 (byte mode).
// [ecCodewordsPerBlock, numBlocksGroup1, dataCodewordsGroup1, numBlocksGroup2, dataCodewordsGroup2]
type EcRow = readonly [number, number, number, number, number];
const EC_TABLE: Record<ECLevel, readonly EcRow[]> = {
  L: [
    [7, 1, 19, 0, 0], [10, 1, 34, 0, 0], [15, 1, 55, 0, 0], [20, 1, 80, 0, 0],
    [26, 1, 108, 0, 0], [18, 2, 68, 0, 0], [20, 2, 78, 0, 0], [24, 2, 97, 0, 0],
    [30, 2, 116, 0, 0], [18, 2, 68, 2, 69],
  ],
  M: [
    [10, 1, 16, 0, 0], [16, 1, 28, 0, 0], [26, 1, 44, 0, 0], [18, 2, 32, 0, 0],
    [24, 2, 43, 0, 0], [16, 4, 27, 0, 0], [18, 4, 31, 0, 0], [22, 2, 38, 2, 39],
    [22, 3, 36, 2, 37], [26, 4, 43, 1, 44],
  ],
  Q: [
    [13, 1, 13, 0, 0], [22, 1, 22, 0, 0], [18, 2, 17, 0, 0], [26, 2, 24, 0, 0],
    [18, 2, 15, 2, 16], [24, 4, 19, 0, 0], [18, 2, 14, 4, 15], [22, 4, 18, 2, 19],
    [20, 4, 16, 4, 17], [24, 6, 19, 2, 20],
  ],
  H: [
    [17, 1, 9, 0, 0], [28, 1, 16, 0, 0], [22, 2, 13, 0, 0], [16, 4, 9, 0, 0],
    [22, 2, 11, 2, 12], [28, 4, 15, 0, 0], [26, 4, 13, 1, 14], [26, 4, 14, 2, 15],
    [24, 4, 12, 4, 13], [28, 6, 15, 2, 16],
  ],
};

function ecRow(version: number, ec: ECLevel): EcRow {
  const row = EC_TABLE[ec][version - 1];
  if (!row) throw new Error("QR: unsupported version");
  return row;
}

// Alignment pattern centers per version (index = version-1).
const ALIGN: readonly (readonly number[])[] = [
  [], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34],
  [6, 22, 38], [6, 24, 42], [6, 26, 46], [6, 28, 50],
];

function dataCodewords(version: number, ec: ECLevel): number {
  const [, g1, d1, g2, d2] = ecRow(version, ec);
  return g1 * d1 + g2 * d2;
}

function chooseVersion(byteLen: number, ec: ECLevel): number {
  for (let v = 1; v <= 10; v++) {
    const ccBits = v <= 9 ? 8 : 16;
    const bits = 4 + ccBits + byteLen * 8;
    const cap = dataCodewords(v, ec) * 8;
    if (bits <= cap) return v;
  }
  throw new Error("QR: data too long for supported versions (1-10)");
}

function buildBitstream(bytes: number[], version: number, ec: ECLevel): number[] {
  const bits: number[] = [];
  const push = (val: number, len: number) => {
    for (let i = len - 1; i >= 0; i--) bits.push((val >> i) & 1);
  };
  push(0b0100, 4); // byte mode
  push(bytes.length, version <= 9 ? 8 : 16);
  for (const b of bytes) push(b, 8);

  const capBits = dataCodewords(version, ec) * 8;
  for (let i = 0; i < 4 && bits.length < capBits; i++) bits.push(0);
  while (bits.length % 8 !== 0) bits.push(0);
  const pads = [0xec, 0x11];
  let pi = 0;
  while (bits.length < capBits) {
    push(pads[pi % 2]!, 8);
    pi++;
  }
  const cw: number[] = [];
  for (let i = 0; i < bits.length; i += 8) {
    let v = 0;
    for (let j = 0; j < 8; j++) v = (v << 1) | bits[i + j]!;
    cw.push(v);
  }
  return cw;
}

function interleave(dataCw: number[], version: number, ec: ECLevel): number[] {
  const [ecCw, g1, d1, g2, d2] = ecRow(version, ec);
  const blocks: { data: number[]; ecc: number[] }[] = [];
  let idx = 0;
  for (let i = 0; i < g1; i++) {
    const data = dataCw.slice(idx, idx + d1);
    idx += d1;
    blocks.push({ data, ecc: rsEncode(data, ecCw) });
  }
  for (let i = 0; i < g2; i++) {
    const data = dataCw.slice(idx, idx + d2);
    idx += d2;
    blocks.push({ data, ecc: rsEncode(data, ecCw) });
  }
  const result: number[] = [];
  const maxData = Math.max(d1, d2);
  for (let i = 0; i < maxData; i++) {
    for (const b of blocks) if (i < b.data.length) result.push(b.data[i]!);
  }
  for (let i = 0; i < ecCw; i++) {
    for (const b of blocks) result.push(b.ecc[i]!);
  }
  return result;
}

function sizeForVersion(v: number): number {
  return 17 + v * 4;
}

// Row-major boolean grid stored as Uint8Array (0/1) for strict-safe indexing.
class BitGrid {
  size: number;
  cells: Uint8Array;
  constructor(size: number) {
    this.size = size;
    this.cells = new Uint8Array(size * size);
  }
  get(r: number, c: number): number {
    return this.cells[r * this.size + c]!;
  }
  set(r: number, c: number, v: boolean | number) {
    this.cells[r * this.size + c] = v ? 1 : 0;
  }
}

function placeFunctionPatterns(grid: BitGrid, reserved: BitGrid, size: number, version: number) {
  const setFinder = (r: number, c: number) => {
    for (let dr = -1; dr <= 7; dr++) {
      for (let dc = -1; dc <= 7; dc++) {
        const rr = r + dr;
        const cc = c + dc;
        if (rr < 0 || rr >= size || cc < 0 || cc >= size) continue;
        reserved.set(rr, cc, true);
        const inRing =
          dr >= 0 && dr <= 6 && dc >= 0 && dc <= 6 &&
          (dr === 0 || dr === 6 || dc === 0 || dc === 6 || (dr >= 2 && dr <= 4 && dc >= 2 && dc <= 4));
        grid.set(rr, cc, inRing);
      }
    }
  };
  setFinder(0, 0);
  setFinder(0, size - 7);
  setFinder(size - 7, 0);

  for (let i = 8; i < size - 8; i++) {
    if (!reserved.get(6, i)) { grid.set(6, i, i % 2 === 0); reserved.set(6, i, true); }
    if (!reserved.get(i, 6)) { grid.set(i, 6, i % 2 === 0); reserved.set(i, 6, true); }
  }

  const centers = ALIGN[version - 1] ?? [];
  for (const r of centers) {
    for (const c of centers) {
      if ((r <= 8 && c <= 8) || (r <= 8 && c >= size - 9) || (r >= size - 9 && c <= 8)) continue;
      for (let dr = -2; dr <= 2; dr++) {
        for (let dc = -2; dc <= 2; dc++) {
          const rr = r + dr;
          const cc = c + dc;
          reserved.set(rr, cc, true);
          grid.set(rr, cc, Math.max(Math.abs(dr), Math.abs(dc)) !== 1);
        }
      }
    }
  }

  grid.set(size - 8, 8, true);
  reserved.set(size - 8, 8, true);

  for (let i = 0; i < 9; i++) {
    reserved.set(8, i, true);
    reserved.set(i, 8, true);
  }
  for (let i = 0; i < 8; i++) {
    reserved.set(8, size - 1 - i, true);
    reserved.set(size - 1 - i, 8, true);
  }
}

function placeData(grid: BitGrid, reserved: BitGrid, size: number, cw: number[]) {
  const bits: number[] = [];
  for (const b of cw) for (let i = 7; i >= 0; i--) bits.push((b >> i) & 1);
  let bi = 0;
  let upward = true;
  for (let col = size - 1; col > 0; col -= 2) {
    if (col === 6) col = 5;
    for (let i = 0; i < size; i++) {
      const row = upward ? size - 1 - i : i;
      for (let c = 0; c < 2; c++) {
        const cc = col - c;
        if (reserved.get(row, cc)) continue;
        grid.set(row, cc, bi < bits.length ? bits[bi] === 1 : false);
        bi++;
      }
    }
    upward = !upward;
  }
}

function maskFn(mask: number, r: number, c: number): boolean {
  switch (mask) {
    case 0: return (r + c) % 2 === 0;
    case 1: return r % 2 === 0;
    case 2: return c % 3 === 0;
    case 3: return (r + c) % 3 === 0;
    case 4: return (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0;
    case 5: return ((r * c) % 2) + ((r * c) % 3) === 0;
    case 6: return (((r * c) % 2) + ((r * c) % 3)) % 2 === 0;
    default: return (((r + c) % 2) + ((r * c) % 3)) % 2 === 0;
  }
}

const EC_BITS: Record<ECLevel, number> = { L: 0b01, M: 0b00, Q: 0b11, H: 0b10 };

function formatBits(ec: ECLevel, mask: number): number {
  const data = (EC_BITS[ec] << 3) | mask;
  let rem = data;
  for (let i = 0; i < 10; i++) {
    rem = (rem << 1) ^ (((rem >> 9) & 1) ? 0x537 : 0);
  }
  return ((data << 10) | rem) ^ 0x5412;
}

function applyFormat(grid: BitGrid, size: number, ec: ECLevel, mask: number) {
  const fmt = formatBits(ec, mask);
  const bit = (i: number) => ((fmt >> i) & 1) === 1;
  for (let i = 0; i <= 5; i++) grid.set(8, i, bit(i));
  grid.set(8, 7, bit(6));
  grid.set(8, 8, bit(7));
  grid.set(7, 8, bit(8));
  for (let i = 9; i <= 14; i++) grid.set(14 - i, 8, bit(i));
  for (let i = 0; i <= 7; i++) grid.set(size - 1 - i, 8, bit(i));
  for (let i = 8; i <= 14; i++) grid.set(8, size - 15 + i, bit(i));
}

/**
 * Generate a QR module matrix (true = dark) for the given text.
 * Byte mode, fixed mask 0 (deterministic, valid).
 */
export function generateQR(text: string, ec: ECLevel = "M"): boolean[][] {
  const bytes = Array.from(new TextEncoder().encode(text));
  const version = chooseVersion(bytes.length, ec);
  const size = sizeForVersion(version);

  const dataCw = buildBitstream(bytes, version, ec);
  const finalCw = interleave(dataCw, version, ec);

  const grid = new BitGrid(size);
  const reserved = new BitGrid(size);
  placeFunctionPatterns(grid, reserved, size, version);
  placeData(grid, reserved, size, finalCw);

  const mask = 0;
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      if (!reserved.get(r, c) && maskFn(mask, r, c)) {
        grid.set(r, c, grid.get(r, c) ? 0 : 1);
      }
    }
  }
  applyFormat(grid, size, ec, mask);

  const out: boolean[][] = [];
  for (let r = 0; r < size; r++) {
    const row: boolean[] = [];
    for (let c = 0; c < size; c++) row.push(grid.get(r, c) === 1);
    out.push(row);
  }
  return out;
}
