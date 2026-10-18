/**
 * IDN homograph support: decode punycode labels and map visually confusable letters to their
 * Latin look-alikes (a small UTS #39 style skeleton), so "metаmask.io" (Cyrillic а) compares as "metamask".
 */

// RFC 3492 decoder (labels only)
export function decodePunycode(label: string): string {
  if (!label.startsWith("xn--")) return label;
  const input = label.slice(4);
  const base = 36, tMin = 1, tMax = 26, skew = 38, damp = 700;
  let n = 128, i = 0, bias = 72;
  const out: number[] = [];
  const basic = input.lastIndexOf("-");
  for (let j = 0; j < (basic > 0 ? basic : 0); j++) out.push(input.charCodeAt(j));
  const digit = (c: number) => (c - 48 < 10 ? c - 22 : c - 65 < 26 ? c - 65 : c - 97 < 26 ? c - 97 : base);
  const adapt = (delta: number, numPoints: number, first: boolean) => {
    delta = first ? Math.floor(delta / damp) : delta >> 1;
    delta += Math.floor(delta / numPoints);
    let k = 0;
    while (delta > ((base - tMin) * tMax) >> 1) { delta = Math.floor(delta / (base - tMin)); k += base; }
    return k + Math.floor(((base - tMin + 1) * delta) / (delta + skew));
  };
  try {
    for (let idx = basic > 0 ? basic + 1 : 0; idx < input.length;) {
      const oldi = i;
      let w = 1;
      for (let k = base; ; k += base) {
        if (idx >= input.length) return label;
        const d = digit(input.charCodeAt(idx++));
        if (d >= base) return label;
        i += d * w;
        const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
        if (d < t) break;
        w *= base - t;
      }
      bias = adapt(i - oldi, out.length + 1, oldi === 0);
      n += Math.floor(i / (out.length + 1));
      i %= out.length + 1;
      out.splice(i++, 0, n);
    }
    return String.fromCodePoint(...out);
  } catch {
    return label;
  }
}

/** Confusables that matter for brand names: Cyrillic, Greek, Armenian and a few Latin extras -> ASCII. */
const CONFUSABLES: Record<string, string> = {
  "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ј": "j", "ѕ": "s", "һ": "h", "ԁ": "d", "ɡ": "g", "ν": "v", "ο": "o", "α": "a", "ε": "e", "ι": "i", "κ": "k", "ρ": "p", "τ": "t", "υ": "u", "χ": "x", "ϲ": "c", "ո": "n", "ս": "u", "ց": "g", "ȩ": "e", "ł": "l", "ı": "i", "ĺ": "l", "ꞓ": "c",
  "ä": "a", "á": "a", "à": "a", "â": "a", "ã": "a", "å": "a", "ā": "a", "é": "e", "è": "e", "ê": "e", "ë": "e", "ē": "e", "ę": "e", "í": "i", "ì": "i", "î": "i", "ï": "i", "ī": "i", "ó": "o", "ò": "o", "ô": "o", "ö": "o", "õ": "o", "ø": "o", "ō": "o", "ú": "u", "ù": "u", "û": "u", "ü": "u", "ū": "u", "ý": "y", "ÿ": "y", "ç": "c", "ñ": "n", "ś": "s", "š": "s", "ž": "z", "ź": "z", "ć": "c", "č": "c", "ğ": "g", "ş": "s", "ţ": "t", "ț": "t",
  "0": "o", "1": "l",
};

export function skeleton(s: string): string {
  let out = "";
  for (const ch of s.normalize("NFKC").toLowerCase()) out += CONFUSABLES[ch] ?? ch;
  return out;
}

/** Decode every punycode label and skeletonize. Returns null when the host has no IDN labels. */
export function homographHost(host: string): string | null {
  if (!/(^|\.)xn--/.test(host)) return null;
  const labels = host.split(".").map((l) => skeleton(decodePunycode(l)));
  return labels.join(".");
}
