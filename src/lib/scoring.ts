import type { Band, Brand, OriginContext, ParsedHost, Signal, SignalLists, Verdict, XIntel } from "./types";
import { isUnderDomain, levenshtein, tokenize } from "./hostname";

export const BLOCK_THRESHOLD = 70;
export const WARN_THRESHOLD = 35;

export interface ScoreContext {
  brands: Brand[];
  lists: SignalLists;
  /** host matched an external blocklist (MetaMask / PhishDestroy / ...) */
  blocklistHit?: string;
  /** host matched an external allowlist (MetaMask allowlist) */
  allowlistHit?: boolean;
  /** user explicitly trusted this registrable domain */
  userAllowed?: boolean;
  /** domain age in days from RDAP, undefined = unknown / not fetched */
  ageDays?: number;
  /** social-platform origin of this navigation (X, Discord, ...) */
  origin?: OriginContext;
  /** optional X resolver result for the brand token in this hostname */
  x?: XIntel;
}

const SOURCE_LABEL: Record<OriginContext["source"], string> = {
  x: "X (Twitter)", discord: "Discord", telegram: "Telegram", reddit: "Reddit", youtube: "YouTube", other: "social media",
};

/** Hostname tokens that are too generic to count as a brand on their own */
const GENERIC = new Set(["app", "www", "mail", "web", "api", "docs", "blog", "shop", "home", "info", "base", "blast", "scroll", "across", "blur", "eigen", "pudgy", "jupiter", "phantom", "ledger", "linea", "zama", "zora", "tensor", "highlight", "manifold", "optimism"]);

export function bandOf(score: number): Band {
  if (score >= BLOCK_THRESHOLD) return "block";
  if (score >= WARN_THRESHOLD) return "warn";
  return "none";
}

/**
 * Pure scoring function. No I/O. Everything the background worker fetched
 * (blocklist hits, RDAP age) is passed in through ctx.
 */
export function score(url: string, p: ParsedHost, ctx: ScoreContext): Verdict {
  const signals: Signal[] = [];
  const base = { url, host: p.host, registrable: p.registrable, at: Date.now() };

  const done = (extra: Partial<Verdict> = {}): Verdict => {
    const total = signals.reduce((s, x) => s + x.weight, 0);
    const clamped = Math.max(0, Math.min(100, total));
    return { ...base, score: clamped, band: bandOf(clamped), signals, needsAgeCheck: false, ...extra };
  };

  // ---- hard allow gates -------------------------------------------------
  if (ctx.userAllowed) {
    signals.push({ id: "user-allow", weight: 0, key: "sig_user_allow" });
    return done();
  }
  if (p.isIp) {
    signals.push({ id: "ip-host", weight: 10, key: "sig_ip_host" });
  }

  const allLabels = [...p.subLabels, p.domainLabel];
  const tokens = tokenize(allLabels);
  const joined = allLabels.join("").toLowerCase().replace(/[^a-z0-9]/g, "");

  // ---- brand matching -----------------------------------------------------
  let matchedBrand: Brand | undefined;
  let brandOfficial = false;
  let brandSignalKind: "official" | "impersonation" | "unverified" | "typo" | undefined;

  for (const b of ctx.brands) {
    if (b.domains.some((d) => isUnderDomain(p.host, d))) {
      matchedBrand = b;
      brandOfficial = true;
      brandSignalKind = "official";
      break;
    }
  }
  if (!brandOfficial) {
    outer: for (const b of ctx.brands) {
      for (const t of b.tokens) {
        const tok = t.toLowerCase();
        const generic = GENERIC.has(tok) || tok.length < 5;
        // Curated brands: substring match in the whole hostname (catches pancakeswapclaim6754).
        // Auto-imported brands: whole-token match only ("yieldfi" must not match "yieldfields").
        const substringOk = b.tier !== "generated" ? joined.includes(tok) : tokens.includes(tok);
        if (!generic && substringOk) {
          matchedBrand = b;
          brandSignalKind = b.domains.length ? "impersonation" : "unverified";
          break outer;
        }
        // exact label match for short/generic tokens (catches blur-claim.xyz, not database.xyz)
        if (generic && tokens.includes(tok) && tokens.length > 1) {
          matchedBrand = b;
          brandSignalKind = b.domains.length ? "impersonation" : "unverified";
          break outer;
        }
        // typosquat: one edit away from a distinctive *curated* brand token (unlswap, metamsk)
        if (b.tier !== "generated" && tok.length >= 6 && tokens.some((x) => x !== tok && Math.abs(x.length - tok.length) <= 1 && levenshtein(x, tok) === 1)) {
          matchedBrand = b;
          brandSignalKind = "typo";
          break outer;
        }
      }
    }
  }

  if (brandOfficial && matchedBrand) {
    signals.push({ id: "brand-official", weight: 0, key: "sig_brand_official", sub: [matchedBrand.name] });
    return done({ brand: matchedBrand.name });
  }
  if (ctx.allowlistHit) {
    signals.push({ id: "allowlist", weight: 0, key: "sig_allowlist" });
    return done();
  }

  // ---- hard block gate ----------------------------------------------------
  if (ctx.blocklistHit) {
    signals.push({ id: "blocklist", weight: 100, key: "sig_blocklist", sub: [ctx.blocklistHit] });
  }

  // ---- hostname heuristics ---------------------------------------------------
  const strongActions = tokens.filter((t) => ctx.lists.actionStrong.includes(t));
  const mediumActions = tokens.filter((t) => ctx.lists.actionMedium.includes(t));
  const hasAction = strongActions.length > 0 || mediumActions.length > 0;

  if (strongActions.length) {
    signals.push({ id: "action-strong", weight: Math.min(30, 20 + (strongActions.length - 1) * 5), key: "sig_action_strong", sub: [[...new Set(strongActions)].join(", ")] });
  } else if (mediumActions.length) {
    signals.push({ id: "action-medium", weight: 10, key: "sig_action_medium", sub: [[...new Set(mediumActions)].join(", ")] });
  }

  if (p.freeHost) {
    const strong = ctx.lists.freeHostsStrong.includes(p.freeHost);
    signals.push({ id: "free-host", weight: strong ? 20 : 8, key: "sig_free_host", sub: [p.freeHost] });
  } else if (p.tld && (hasAction || matchedBrand)) {
    // A TLD never scores on its own: every extension is used by legitimate projects today.
    // Heavily abused ones (.top, .bond, .cfd ...) only add weight next to a bait word or brand hit.
    const tldLast = p.tld.split(".").pop() ?? p.tld;
    if (ctx.lists.tldStrong.includes(tldLast)) signals.push({ id: "tld-strong", weight: 15, key: "sig_tld_strong", sub: ["." + tldLast] });
  }

  // true once a brand-related signal was actually added (origin signals key off this, not the raw match)
  let brandFlagged = false;
  if (matchedBrand && brandSignalKind && brandSignalKind !== "official") {
    brandFlagged = true;
    if (brandSignalKind === "impersonation" && matchedBrand.tier !== "generated") {
      signals.push({ id: "brand-impersonation", weight: 40, key: "sig_brand_impersonation", sub: [matchedBrand.name, matchedBrand.domains.slice(0, 2).join(", ")] });
    } else if (brandSignalKind === "impersonation") {
      // auto-imported brand: names are often common words and domains drift (kamino.finance vs kamino.com),
      // so it only counts alongside an action word or free hosting
      if (hasAction || p.freeHost) signals.push({ id: "brand-impersonation-weak", weight: 30, key: "sig_brand_impersonation", sub: [matchedBrand.name, matchedBrand.domains.slice(0, 2).join(", ")] });
      else brandFlagged = false;
    } else if (brandSignalKind === "typo") {
      signals.push({ id: "brand-typo", weight: 35, key: "sig_brand_typo", sub: [matchedBrand.name] });
    } else if (hasAction || p.freeHost) {
      // brand with unverified official domain only counts together with another signal
      signals.push({ id: "brand-unverified", weight: 25, key: "sig_brand_unverified", sub: [matchedBrand.name] });
    } else {
      brandFlagged = false;
    }
  }

  // digits glued to words: pancakeswapclaim6754, claim-arb2
  if (/[a-z]\d{2,}/.test(p.domainLabel.replace(/-/g, "")) && (hasAction || matchedBrand)) {
    signals.push({ id: "digits", weight: 10, key: "sig_digits" });
  }

  // "rewards-<something>" style even when the brand is unknown to us
  if (!matchedBrand && hasAction && /-/.test(p.domainLabel) && tokens.length >= 2) {
    signals.push({ id: "action-hyphen", weight: 10, key: "sig_action_hyphen" });
  }

  if (p.subLabels.length >= 3 || p.host.length > 40) {
    signals.push({ id: "long-host", weight: 5, key: "sig_long_host" });
  }

  // ---- social origin ----------------------------------------------------------
  // Only ever raises the score: hijacked official accounts post scam links too.
  const o = ctx.origin;
  if (o) {
    signals.push({ id: "origin-social", weight: 10, key: "sig_origin_social", sub: [SOURCE_LABEL[o.source]] });
    const poster = o.poster?.toLowerCase().replace(/^@/, "");
    if (matchedBrand && brandFlagged && poster) {
      const official = matchedBrand.x?.toLowerCase().replace(/^@/, "");
      // a poster whose handle carries the brand's own token is not "someone else" (yieldfields_rh vs yieldfields.fun)
      // whole domain label, not just the brand token: "uniswap_claims" must not get a pass for uniswap-rewards.com
      const label = p.domainLabel.replace(/[^a-z0-9]/g, "");
      const posterCarriesHost = label.length >= 6 && poster.replace(/[^a-z0-9]/g, "").includes(label);
      if (official && poster !== official && !posterCarriesHost) {
        signals.push({ id: "poster-mismatch", weight: matchedBrand.tier === "generated" ? 15 : 30, key: "sig_poster_mismatch", sub: ["@" + poster, "@" + official] });
      } else if (!official && /(claim|airdrop|drop|reward|official|support|mint|giveaway|bonus)/i.test(poster)) {
        signals.push({ id: "poster-name", weight: 15, key: "sig_poster_name", sub: ["@" + poster] });
      }
    }
    if (o.isReply && (hasAction || matchedBrand)) {
      signals.push({ id: "poster-reply", weight: 10, key: "sig_poster_reply" });
    }
    if (o.display && o.display.toLowerCase() !== p.host && !p.host.endsWith(o.display.toLowerCase())) {
      signals.push({ id: "display-mismatch", weight: 10, key: "sig_display_mismatch", sub: [o.display] });
    }
  }

  // ---- X resolver (optional, only when an API key is configured) ----------------
  const xi = ctx.x;
  let xCleared = false;
  if (xi?.official && xi.confidence >= 0.5) {
    const off = xi.official;
    const strong = off.followers >= 5000 || /business|government/i.test(off.verifiedType ?? "");
    const hostMatches = off.domains.some((d) => isUnderDomain(p.host, d));
    if (hostMatches && strong) {
      // the project's own X account links to exactly this domain: treat like an official domain
      signals.push({ id: "x-domain-match", weight: -100, key: "sig_x_domain_match", sub: ["@" + off.handle] });
      xCleared = true;
    } else if (!hostMatches && off.domains.length && (brandFlagged || hasAction)) {
      signals.push({ id: "x-domain-mismatch", weight: 25, key: "sig_x_domain_mismatch", sub: ["@" + off.handle, off.domains[0]] });
    }
    const poster = o?.poster?.toLowerCase().replace(/^@/, "");
    if (poster && poster !== off.handle.toLowerCase() && !hostMatches && (brandFlagged || hasAction)) {
      if (!signals.some((s) => s.id === "poster-mismatch")) {
        signals.push({ id: "poster-mismatch", weight: 30, key: "sig_poster_mismatch", sub: ["@" + poster, "@" + off.handle] });
      }
    }
  }
  if (xi?.poster && o?.poster && !xCleared && (hasAction || brandFlagged)) {
    const pp = xi.poster;
    const young = pp.ageDays !== undefined && pp.ageDays < 30;
    if (young || pp.followers < 100) {
      signals.push({ id: "x-poster-weak", weight: 15, key: "sig_x_poster_weak", sub: ["@" + pp.handle, String(pp.followers), String(pp.ageDays === undefined ? "?" : Math.floor(pp.ageDays))] });
    }
  }

  // ---- domain age -----------------------------------------------------------
  if (ctx.ageDays !== undefined) {
    if (ctx.ageDays < 7) signals.push({ id: "age-7", weight: 25, key: "sig_age_days", sub: [String(Math.max(0, Math.floor(ctx.ageDays)))] });
    else if (ctx.ageDays < 30) signals.push({ id: "age-30", weight: 15, key: "sig_age_days", sub: [String(Math.floor(ctx.ageDays))] });
    else if (ctx.ageDays < 90) signals.push({ id: "age-90", weight: 5, key: "sig_age_days", sub: [String(Math.floor(ctx.ageDays))] });
    else if (ctx.ageDays > 365 * 2) signals.push({ id: "age-old", weight: -10, key: "sig_age_years", sub: [String(Math.floor(ctx.ageDays / 365))] });
  }

  const v = done({ brand: matchedBrand?.name, ageDays: ctx.ageDays });

  // Combination rule from the research: brand + action word + (free host | fresh domain) is near-certain.
  if (matchedBrand && hasAction && (p.freeHost || (ctx.ageDays !== undefined && ctx.ageDays < 30))) {
    if (v.score < BLOCK_THRESHOLD) {
      signals.push({ id: "combo", weight: BLOCK_THRESHOLD - v.score, key: "sig_combo" });
      return done({ brand: matchedBrand.name, ageDays: ctx.ageDays });
    }
  }

  // Age lookup is worth doing only when it could move the band.
  const floor = ctx.origin ? 10 : 20;
  v.needsAgeCheck = ctx.ageDays === undefined && !ctx.blocklistHit && !p.freeHost && v.score >= floor && v.score < BLOCK_THRESHOLD;
  // Which name should the X layer look up? The matched brand token, else the most brand-like hostname token.
  if (!ctx.x && !ctx.blocklistHit && v.score >= floor) {
    const actionSet = new Set([...ctx.lists.actionStrong, ...ctx.lists.actionMedium]);
    const candidate = matchedBrand
      ? matchedBrand.tokens.find((t) => joined.includes(t.toLowerCase())) ?? matchedBrand.tokens[0]
      : tokens.filter((t) => t.length >= 5 && !actionSet.has(t) && !GENERIC.has(t)).sort((a, b) => b.length - a.length)[0];
    if (candidate) v.xToken = candidate;
  }
  return v;
}
