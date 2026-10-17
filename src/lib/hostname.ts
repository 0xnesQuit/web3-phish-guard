import { parse } from "tldts";
import type { ParsedHost } from "./types";

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

/**
 * Parse a URL's hostname into the pieces the heuristics need.
 * Free hosts (vercel.app, pages.dev...) are treated as the "TLD" so the user's
 * project label becomes the domainLabel, which is where scams put brand+action words.
 */
export function parseHost(urlOrHost: string, freeHosts: string[] = []): ParsedHost | null {
  let host: string;
  try {
    host = urlOrHost.includes("://") ? new URL(urlOrHost).hostname : urlOrHost;
  } catch {
    return null;
  }
  host = host.toLowerCase().replace(/\.$/, "");
  if (!host) return null;

  if (IPV4.test(host) || host.startsWith("[")) {
    return { host, registrable: host, tld: "", subLabels: [], domainLabel: host, isIp: true };
  }

  const r = parse(host, { allowPrivateDomains: false });
  let registrable = r.domain ?? host;
  let tld = r.publicSuffix ?? "";
  let freeHost: string | undefined;

  // Shared hosting: treat "<user>.vercel.app" like a registrable domain of its own.
  for (const fh of freeHosts) {
    if (host === fh || host.endsWith("." + fh)) {
      freeHost = fh;
      const rest = host.slice(0, host.length - fh.length - 1);
      const parts = rest.split(".").filter(Boolean);
      if (parts.length) {
        registrable = parts[parts.length - 1] + "." + fh;
        tld = fh;
      }
      break;
    }
  }

  const domainLabel = tld && registrable.endsWith("." + tld) ? registrable.slice(0, -(tld.length + 1)) : registrable;
  const subPart = host === registrable ? "" : host.slice(0, host.length - registrable.length - 1);
  const subLabels = subPart ? subPart.split(".").filter(Boolean) : [];

  return { host, registrable, tld, subLabels, domainLabel, isIp: false, freeHost };
}

/** Split labels on hyphens/underscores/digits into lowercase word tokens. */
export function tokenize(labels: string[]): string[] {
  const out: string[] = [];
  for (const l of labels) {
    for (const t of l.toLowerCase().split(/[-_.]+|(?<=\D)(?=\d)|(?<=\d)(?=\D)/)) {
      if (t && /[a-z]/.test(t)) out.push(t);
    }
  }
  return out;
}

export function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  if (!a.length) return b.length;
  if (!b.length) return a.length;
  let prev = new Array(b.length + 1).fill(0).map((_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    for (let j = 1; j <= b.length; j++) {
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
    prev = cur;
  }
  return prev[b.length];
}

/** host equals domain or is a subdomain of it */
export function isUnderDomain(host: string, domain: string): boolean {
  return host === domain || host.endsWith("." + domain);
}
