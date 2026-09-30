/**
 * Payload generators — the lists Burp's Intruder builds for you and Nullhawk's fuzzer
 * otherwise makes you bring: number ranges, charset brute-force, case permutations, and
 * wordlist mutation for password spraying.
 *
 * Everything is capped. A brute-force over a full charset is exponential, and a UI that
 * tries to materialise ninety million strings helps nobody — so each generator stops at
 * a ceiling and says it was truncated, which is the honest thing to show.
 */

const CAP = 10000;

export interface Generated {
  items: string[];
  total: number;
  truncated: boolean;
}

export const CHARSETS: Record<string, string> = {
  lowercase: "abcdefghijklmnopqrstuvwxyz",
  uppercase: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  digits: "0123456789",
  "lower+digits": "abcdefghijklmnopqrstuvwxyz0123456789",
  alphanumeric: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
  hex: "0123456789abcdef",
  special: "!@#$%^&*()-_=+",
};

/** Numbers from `from` to `to` (inclusive) by `step`, optionally zero-padded. */
export function numberRange(from: number, to: number, step: number, pad: number): Generated {
  const items: string[] = [];
  let total = 0;
  const dir = to >= from ? 1 : -1;
  const s = Math.abs(step) || 1;
  for (let n = from; dir > 0 ? n <= to : n >= to; n += dir * s) {
    total++;
    if (items.length < CAP) {
      const str = Math.abs(n).toString();
      items.push((n < 0 ? "-" : "") + (pad > 0 ? str.padStart(pad, "0") : str));
    }
  }
  return { items, total, truncated: total > items.length };
}

/** Every string over `charset` from `minLen` to `maxLen` — capped. */
export function bruteForce(charset: string, minLen: number, maxLen: number): Generated {
  const chars = [...new Set([...charset])];
  const items: string[] = [];
  let total = 0;

  const countFor = (len: number) => Math.pow(chars.length, len);
  for (let len = minLen; len <= maxLen; len++) total += countFor(len);

  const build = (prefix: string, len: number) => {
    if (items.length >= CAP) return;
    if (len === 0) {
      items.push(prefix);
      return;
    }
    for (const c of chars) {
      if (items.length >= CAP) return;
      build(prefix + c, len - 1);
    }
  };
  for (let len = Math.max(1, minLen); len <= maxLen && items.length < CAP; len++) {
    build("", len);
  }
  return { items, total, truncated: total > items.length };
}

/** Every case variant of a word (toggle each letter's case) — capped. */
export function casePermutations(word: string): Generated {
  const letters = [...word];
  const positions = letters.map((c, i) => (/[a-z]/i.test(c) ? i : -1)).filter((i) => i >= 0);
  const total = Math.pow(2, positions.length);
  const items: string[] = [];
  for (let mask = 0; mask < total && items.length < CAP; mask++) {
    const chars = [...letters];
    positions.forEach((pos, bit) => {
      const ch = chars[pos];
      if (ch === undefined) return;
      chars[pos] = (mask >> bit) & 1 ? ch.toUpperCase() : ch.toLowerCase();
    });
    items.push(chars.join(""));
  }
  return { items, total, truncated: total > items.length };
}

export interface MutateOptions {
  capitalize: boolean;
  leet: boolean;
  appendYears: boolean;
  appendCommon: boolean;
}

const LEET: Record<string, string> = { a: "@", e: "3", i: "1", o: "0", s: "$", t: "7" };

/** Password-spray style mutation of a base wordlist. */
export function mutateWordlist(words: string[], opts: MutateOptions): Generated {
  const out = new Set<string>();
  const years = currentYears();
  const common = ["123", "1234", "12345", "!", "@", "#", "1", "01", "007", "69", "420"];

  for (const raw of words) {
    const w = raw.trim();
    if (w === "") continue;
    const bases = new Set<string>([w]);
    if (opts.capitalize) bases.add(w.charAt(0).toUpperCase() + w.slice(1));
    if (opts.leet) {
      for (const b of [...bases]) {
        bases.add([...b].map((c) => LEET[c.toLowerCase()] ?? c).join(""));
      }
    }
    for (const b of bases) {
      out.add(b);
      if (opts.appendYears) for (const y of years) out.add(b + y);
      if (opts.appendCommon) for (const c of common) out.add(b + c);
    }
    if (out.size >= CAP) break;
  }
  const all = [...out];
  return { items: all.slice(0, CAP), total: all.length, truncated: all.length > CAP };
}

function currentYears(): string[] {
  const now = new Date().getFullYear();
  const ys: string[] = [];
  for (let y = now; y >= now - 6; y--) ys.push(String(y));
  return ys;
}
