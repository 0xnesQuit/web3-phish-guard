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
  label: string;
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

export interface ProviderEvent {
  kind: "auto-connect" | "risky-sign" | "risky-tx" | "chain-switch";
  method: string;
  detail: string;
  msSinceLoad: number;
  hadGesture: boolean;
}
