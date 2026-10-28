/**
 * Seeded PRNG using the Mulberry32 algorithm.
 * Guarantees 100% deterministic, reproducible mock arena generation across sessions.
 */
export function createMulberry32(seed: number) {
  let s = Math.floor(seed) >>> 0;
  return function next(): number {
    s = (s + 0x6d2b79f5) >>> 0;
    let t = Math.imul(s ^ (s >>> 15), 1 | s);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export class DeterministicRng {
  private prng: () => number;

  constructor(seed: number = 0x429496) {
    this.prng = createMulberry32(seed);
  }

  nextFloat(): number {
    return this.prng();
  }

  nextInt(min: number, max: number): number {
    return Math.floor(this.nextFloat() * (max - min + 1)) + min;
  }

  nextChoice<T>(items: readonly T[]): T {
    if (items.length === 0) {
      throw new Error('Cannot pick from empty array');
    }
    const idx = Math.floor(this.nextFloat() * items.length);
    return items[idx];
  }
}
