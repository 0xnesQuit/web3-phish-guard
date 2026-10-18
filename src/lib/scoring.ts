import type { Band, Brand, OriginContext, PageSocials, ParsedHost, Signal, SignalLists, Verdict, XIntel } from "./types";
import { isUnderDomain, levenshtein, tokenize } from "./hostname";

export const BLOCK_THRESHOLD = 70;
export const WARN_THRESHOLD = 35;

export interface ScoreContext {
  brands: Brand[];
  lists: SignalLists;
  /** host matched an external blocklist (MetaMask / PhishDestroy / ...) */
  blocklistHit?: string;
  /** a listed phishing host on the same free host shares a distinctive token with this one */
  siblingHit?: string;
  /** the hostname carries a token that many listed phishing domains share (brand under attack) */
  attacked?: { token: string; count: number; example: string };
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
  /** X handles linked from the page itself */
  socials?: PageSocials;
  /** lowercase X handle -> brand (from lists.brandByHandle) */
  handleIndex?: Map<string, Brand>;
}

const SOURCE_LABEL: Record<OriginContext["source"], string> = {
  x: "X (Twitter)", discord: "Discord", telegram: "Telegram", reddit: "Reddit", youtube: "YouTube", other: "social media",
};

/** Hostname tokens that are too generic to count as a brand on their own */
const GENERIC = new Set(["app", "www", "mail", "web", "api", "docs", "blog", "shop", "home", "info", "base", "blast", "scroll", "across", "blur", "eigen", "pudgy", "jupiter", "phantom", "ledger", "linea", "zama", "zora", "tensor", "highlight", "manifold", "optimism"]);

/** "papertradefnd" -> "papertrade", "officialzama" -> "zama": clones glue affixes onto the real name. */
export function stripCloneAffixes(token: string): string {
  const AFFIX = ["foundation", "official", "finance", "protocol", "network", "testnet", "mainnet", "labs", "team", "dao", "fnd", "fdn", "app", "xyz", "eth", "sol", "ico", "ido", "tge", "token", "coin", "portal", "claim", "drop", "net"];
  let t = token.toLowerCase();
  for (let pass = 0; pass < 2; pass++) {
    for (const a of AFFIX) {
      if (t.length - a.length >= 4 && t.endsWith(a)) { t = t.slice(0, -a.length); break; }
      if (t.length - a.length >= 4 && t.startsWith(a)) { t = t.slice(a.length); break; }
    }
  }
  return t;
}

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
  if (ctx.lists.trusted.some((d) => isUnderDomain(p.host, d))) {
    // Known infrastructure (explorers, exchanges, wallets...). Beats heuristics and single-source blocklist hits:
    // feeds do list these by mistake (PhishDestroy had basescan.org, ScamSniffer goerli.basescan.org on 2026-10-17).
    signals.push({ id: "trusted", weight: 0, key: "sig_trusted" });
    return done();
  }
  if (p.isIp) {
    signals.push({ id: "ip-host", weight: 10, key: "sig_ip_host" });
  }

  const allLabels = [...p.subLabels, p.domainLabel];
  const tokens = tokenize(allLabels);
  const strippedTokens = tokens.map(stripCloneAffixes);
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
        // Auto-imported: whole token, or whole token after stripping clone affixes ("papertradefnd" -> "papertrade").
        const substringOk = b.tier !== "generated" ? joined.includes(tok) : tokens.includes(tok) || strippedTokens.includes(tok);
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
    // MetaMask and ScamSniffer entries are reviewed; PhishDestroy is broader and noisier, so alone it only warns
    // and becomes a block when any local heuristic agrees (the combination is added further down).
    const weight = ctx.blocklistHit === "phishdestroy" ? 50 : ctx.blocklistHit === "community-auto" ? 70 : 100;
    signals.push({ id: "blocklist", weight, key: "sig_blocklist", sub: [ctx.blocklistHit] });
  }

  if (ctx.siblingHit && !ctx.blocklistHit) {
    signals.push({ id: "blocklist-sibling", weight: 45, key: "sig_blocklist_sibling", sub: [ctx.siblingHit] });
  }
  // deferred: the attacked-brand signal needs hasAction / freeHost / fresh, computed below

  const fresh = ctx.ageDays !== undefined && ctx.ageDays < 30;
  // Phishing domains live days, not years (avg 8.6 days; re-registrations get a new registration date).
  // A registrable domain older than a year that carries a brand name is brand sprawl (bybitglobal.com), not a clone.
  const old = ctx.ageDays !== undefined && ctx.ageDays > 365;

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
      signals.push({ id: "brand-impersonation", weight: old ? 10 : 40, key: "sig_brand_impersonation", sub: [matchedBrand.name, matchedBrand.domains.slice(0, 2).join(", ")] });
    } else if (brandSignalKind === "impersonation") {
      // auto-imported brand: names are often common words and domains drift (kamino.finance vs kamino.com),
      // so it only counts alongside an action word or free hosting
      // a bait word is required: a free host alone is where hobby projects live ("my-portfolio.netlify.app")
      if (hasAction) signals.push({ id: "brand-impersonation-weak", weight: 30, key: "sig_brand_impersonation", sub: [matchedBrand.name, matchedBrand.domains.slice(0, 2).join(", ")] });
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

  // brand as a subdomain of an unrelated registrable domain: coinmarketcap.communityphase.app, metamask.evil.xyz
  if (matchedBrand && brandFlagged && p.subLabels.length) {
    const subJoined = p.subLabels.join("").toLowerCase();
    if (matchedBrand.tokens.some((tk) => tk.length >= 5 && subJoined.includes(tk.toLowerCase()))) {
      signals.push({ id: "brand-subdomain", weight: 15, key: "sig_brand_subdomain", sub: [matchedBrand.name, p.registrable] });
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

  // brand under attack: the token is shared by several listed phishing domains. Never alone (the real project's
  // own site carries the same token), only next to a bait word, free host, fresh registration or a shortener.
  let attackedFlagged = false;
  if (ctx.attacked && !ctx.blocklistHit && !ctx.siblingHit && (hasAction || p.freeHost || fresh || ctx.origin?.shortener)) {
    signals.push({ id: "attacked-brand", weight: 40, key: "sig_attacked_brand", sub: [ctx.attacked.token, String(ctx.attacked.count), ctx.attacked.example] });
    attackedFlagged = true;
  }

  // bait word in the path of an already suspicious host: coinmarketcap.evil.app/vote, brand-clone.xyz/claim, 0-day-old.xyz/register
  if (brandFlagged || attackedFlagged || p.freeHost || fresh) {
    const path = (url.split("://")[1]?.slice(p.host.length) ?? "").split(/[?#]/)[0].toLowerCase();
    const seg = path.split("/").filter(Boolean)[0] ?? "";
    if (seg && (ctx.lists.actionStrong.includes(seg) || ctx.lists.actionMedium.includes(seg))) {
      signals.push({ id: "action-path", weight: 10, key: "sig_action_path", sub: ["/" + seg] });
    }
  }

  // token / wallet address in the URL of a bait page ("?life=<pump.fun mint>", "/claim/0xabc...")
  if ((hasAction || p.freeHost || matchedBrand) && /(0x[0-9a-fA-F]{40}|[1-9A-HJ-NP-Za-km-z]{32,44})/.test(url.split("://")[1]?.slice(p.host.length) ?? "")) {
    signals.push({ id: "address-in-url", weight: 10, key: "sig_address_in_url" });
  }

  // ---- social origin ----------------------------------------------------------
  // Only ever raises the score: hijacked official accounts post scam links too.
  const o = ctx.origin;
  if (o) {
    signals.push({ id: "origin-social", weight: 10, key: "sig_origin_social", sub: [SOURCE_LABEL[o.source]] });
    if (o.shortener && (hasAction || attackedFlagged || brandFlagged || fresh || p.freeHost)) {
      signals.push({ id: "shortener", weight: 10, key: "sig_shortener", sub: [o.shortener] });
    }
    const poster = o.poster?.toLowerCase().replace(/^@/, "");
    // Clone-handle shapes: brand + fdn/fnd/foundation/official/team..., trailing "_" or digits (@papertrade_fdn_, @Uniswap_2)
    const CLONE_HANDLE = /(claim|airdrop|drop|reward|official|support|mint|giveaway|bonus|fdn|fnd|foundation|team|labs|ico|presale|sale|launch|promo|help|verify)/i;
    const cloneShape = !!poster && (CLONE_HANDLE.test(poster) || /[_]$/.test(poster) || /[a-z]_?\d{1,3}$/.test(poster) || /__/.test(poster));
    if (poster && cloneShape && (hasAction || fresh || brandFlagged || p.freeHost) && !(matchedBrand && brandFlagged && matchedBrand.x)) {
      signals.push({ id: "poster-name", weight: 15, key: "sig_poster_name", sub: ["@" + poster] });
    }
    if (matchedBrand && brandFlagged && poster) {
      const official = matchedBrand.x?.toLowerCase().replace(/^@/, "");
      // a poster whose handle carries the brand's own token is not "someone else" (yieldfields_rh vs yieldfields.fun)
      // whole domain label, not just the brand token: "uniswap_claims" must not get a pass for uniswap-rewards.com
      const label = p.domainLabel.replace(/[^a-z0-9]/g, "");
      const posterCarriesHost = label.length >= 6 && poster.replace(/[^a-z0-9]/g, "").includes(label);
      if (official && poster !== official && !posterCarriesHost) {
        signals.push({ id: "poster-mismatch", weight: matchedBrand.tier === "generated" ? 15 : 30, key: "sig_poster_mismatch", sub: ["@" + poster, "@" + official] });
      }
    }
    if (o.isReply && (hasAction || matchedBrand)) {
      signals.push({ id: "poster-reply", weight: 10, key: "sig_poster_reply" });
    }
    // Link text named one domain, the page opened on another: deliberate deception, near-certain scam.
    const disp = o.display?.toLowerCase();
    if (disp && disp !== p.host && !isUnderDomain(p.host, disp) && !isUnderDomain(disp, p.registrable)) {
      signals.push({ id: "display-mismatch", weight: 40, key: "sig_display_mismatch", sub: [o.display!] });
    }
  }

  // ---- page links to a real project's X account while living elsewhere --------------
  // Clones paste the victim project's official X/Discord links in the footer to look legitimate.
  // Only on hosts that already look like bait (aggregators and news sites link to many projects).
  if (ctx.socials?.xHandles.length && ctx.handleIndex && (hasAction || p.freeHost || fresh || brandFlagged || attackedFlagged || !!o)) {
    for (const h of ctx.socials.xHandles.slice(0, 8)) {
      const b = ctx.handleIndex.get(h.toLowerCase());
      if (!b || !b.domains.length) continue;
      if (b.domains.some((d) => isUnderDomain(p.host, d))) continue; // it is the project's own site
      signals.push({ id: "page-official-x", weight: 35, key: "sig_page_official_x", sub: ["@" + h, b.name, b.domains[0]] });
      if (!matchedBrand) matchedBrand = b;
      brandFlagged = true;
      break;
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
    } else if (!hostMatches && off.domains.length && (brandFlagged || hasAction || fresh) && !old) {
      signals.push({ id: "x-domain-mismatch", weight: 25, key: "sig_x_domain_mismatch", sub: ["@" + off.handle, off.domains[0]] });
    }
    const poster = o?.poster?.toLowerCase().replace(/^@/, "");
    if (poster && poster !== off.handle.toLowerCase() && !hostMatches && (brandFlagged || hasAction || fresh) && !old) {
      if (!signals.some((s) => s.id === "poster-mismatch")) {
        signals.push({ id: "poster-mismatch", weight: 30, key: "sig_poster_mismatch", sub: ["@" + poster, "@" + off.handle] });
      }
    }
  }
  if (xi?.poster && o?.poster && !xCleared && (hasAction || brandFlagged || fresh || o.display)) {
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

  // Combination rules from the research: brand + action word + (free host | fresh domain) is near-certain,
  // and so is a free host whose label is nothing but bait words (claim-evm-airdrop.netlify.app).
  const strongBait = new Set(strongActions).size >= 2;
  if ((matchedBrand && hasAction && (p.freeHost || fresh)) || (p.freeHost && strongBait && ctx.lists.freeHostsStrong.includes(p.freeHost))) {
    if (v.score < BLOCK_THRESHOLD) {
      signals.push({ id: "combo", weight: BLOCK_THRESHOLD - v.score, key: "sig_combo" });
      return done({ brand: matchedBrand?.name, ageDays: ctx.ageDays });
    }
  }

  // Age lookup is worth doing only when it could move the band.
  const floor = ctx.origin ? 10 : 20;
  v.needsAgeCheck = ctx.ageDays === undefined && !ctx.blocklistHit && !p.freeHost && v.score >= floor && v.score < BLOCK_THRESHOLD;
  // Which name should the X layer look up? The matched brand token, else the most brand-like hostname token.
  if (!ctx.x && !ctx.blocklistHit && v.score >= floor) {
    const actionSet = new Set([...ctx.lists.actionStrong, ...ctx.lists.actionMedium]);
    const raw = matchedBrand
      ? matchedBrand.tokens.find((t) => joined.includes(t.toLowerCase())) ?? matchedBrand.tokens[0]
      : tokens.filter((t) => t.length >= 5 && !actionSet.has(t) && !GENERIC.has(t)).sort((a, b) => b.length - a.length)[0];
    if (ctx.attacked) v.xToken = ctx.attacked.token;
    else if (raw) v.xToken = stripCloneAffixes(raw);
  }
  return v;
}
