export interface Brand {
  name: string;
  /** lowercase alnum tokens that identify the brand inside a hostname */
  tokens: string[];
  /** registrable official domains (eTLD+1). Empty = brand known but official domain unverified */
  domains: string[];
  x?: string;
  note?: string;
  /** seed = hand-curated high-profile brand; generated = auto-imported (DefiLlama), lower confidence */
  tier?: "seed" | "generated";
}

export interface SignalLists {
  /** registrable domains of well-known crypto infrastructure; never flagged */
  trusted: string[];
  actionStrong: string[];
  actionMedium: string[];
  freeHostsStrong: string[];
  freeHostsWeak: string[];
  tldStrong: string[];
  tldWeak: string[];
}

export interface Signal {
  id: string;
  weight: number;
  /** chrome.i18n message key; rendered at display time in the user's language */
  key: string;
  /** substitutions for $1, $2 ... in the message */
  sub?: string[];
}

export type Band = "none" | "warn" | "block";

export interface Verdict {
  url: string;
  host: string;
  registrable: string;
  score: number;
  band: Band;
  signals: Signal[];
  brand?: string;
  /** true when RDAP age lookup would change the outcome */
  needsAgeCheck: boolean;
  /** brand token worth resolving on X (set when the X layer could change the outcome) */
  xToken?: string;
  ageDays?: number;
  at: number;
}

export interface ParsedHost {
  host: string;
  registrable: string;
  tld: string;
  /** labels left of the registrable domain, e.g. ["claim"] for claim.foo.com */
  subLabels: string[];
  /** the registrable domain's own label without TLD, e.g. "rewards-axisrobotics" */
  domainLabel: string;
  isIp: boolean;
  /** the free-host suffix if the registrable domain is a shared hosting domain */
  freeHost?: string;
}

/** Where the navigation came from, when a social platform was the referrer. */
export interface OriginContext {
  source: "x" | "discord" | "telegram" | "reddit" | "youtube" | "other";
  /** handle of the account whose post carried the link (without @) */
  poster?: string;
  posterVerified?: boolean;
  /** the post was a reply under someone else's post (classic scam placement) */
  isReply?: boolean;
  /** the display text X showed for the link, e.g. "rewards-axisrobotics.xyz" */
  display?: string;
  /** hostname of the clicked href (t.co for wrapped links, else the direct target) */
  target?: string;
  at: number;
}

/** What the optional X resolver learned (brand token -> official account, poster profile). */
export interface XIntel {
  token: string;
  official?: { handle: string; domains: string[]; followers: number; verifiedType?: string };
  confidence: number;
  poster?: { handle: string; followers: number; ageDays?: number; domains: string[] };
}

export interface ProviderEvent {
  kind: "auto-connect" | "risky-sign" | "risky-tx" | "chain-switch";
  method: string;
  /** machine-readable detail code, mapped to an i18n key in the background */
  detail: string;
  /** optional literal to substitute (e.g. a typed-data primaryType) */
  param?: string;
  msSinceLoad: number;
  hadGesture: boolean;
}
