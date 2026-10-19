import type { Band, Brand, OriginContext, PageSocials, ParsedHost, Signal, SignalLists, Verdict, XIntel } from "./types";
import { isUnderDomain, levenshtein, tokenize } from "./hostname";
import { isRedirector } from "./origin";
import { homographHost } from "./idn";

/** token -> generated-tier brand, built once per brands array (the array is replaced, never mutated). */
const generatedIndexCache = new WeakMap<Brand[], Map<string, Brand>>();
function generatedIndex(brands: Brand[]): Map<string, Brand> {
  let m = generatedIndexCache.get(brands);
  if (m) return m;
  m = new Map();
  for (const b of brands) {
    if (b.tier !== "generated") continue;
    for (const t of b.tokens) {
      const k = t.toLowerCase();
      if (k.length >= 5 && !GENERIC.has(k) && !m.has(k)) m.set(k, b);
    }
  }
  generatedIndexCache.set(brands, m);
  return m;
}

export const BLOCK_THRESHOLD = 70;
export const WARN_THRESHOLD = 35;

export interface ScoreContext {
  brands: Brand[];
  lists: SignalLists;
  /** host matched an external blocklist (MetaMask / PhishDestroy / ...) */
  blocklistHit?: string;
  /** the registrable domain is in the top ~50k most visited sites: one feed's say-so never blocks it */
  popular?: boolean;
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
  /** brand token -> brand (from lists.brandByToken) */
  brandByToken?: Map<string, Brand>;
}

const SOURCE_LABEL: Record<OriginContext["source"], string> = {
  x: "X (Twitter)", discord: "Discord", telegram: "Telegram", reddit: "Reddit", youtube: "YouTube", ads: "a search ad", other: "social media",
};

/** Hostname tokens that are too generic to count as a brand on their own */
const curatedTokens = new WeakMap<Brand[], Set<string>>();
/** tokens of curated (seed / trusted) brands only */
function curatedTokenSet(brands: Brand[]): Set<string> {
  let s = curatedTokens.get(brands);
  if (!s) {
    s = new Set();
    for (const b of brands) { if (b.tier === "generated") continue; for (const t of b.tokens) { const k = t.toLowerCase(); if (k.length >= 5 && !GENERIC.has(k)) { s.add(k); s.add(stripCloneAffixes(k)); } } }
    curatedTokens.set(brands, s);
  }
  return s;
}
const brandTokens = new WeakMap<Brand[], Set<string>>();
/** every brand token (plain and affix-stripped), cached per brand array */
function brandTokenSet(brands: Brand[]): Set<string> {
  let s = brandTokens.get(brands);
  if (!s) {
    s = new Set();
    for (const b of brands) for (const t of b.tokens) { const k = t.toLowerCase(); s.add(k); s.add(stripCloneAffixes(k)); }
    brandTokens.set(brands, s);
  }
  return s;
}

/** labels that say nothing about a site: never the "second token" that lets a short brand name match */
const HOST_NOISE = new Set(["www", "m", "mail", "app", "api", "web", "my", "go", "en", "de", "fr", "es", "it", "ru", "cn", "jp", "shop", "store", "blog", "docs", "help", "support"]);

const GENERIC = new Set(["app", "www", "mail", "web", "api", "docs", "blog", "shop", "home", "info", "base", "blast", "scroll", "across", "blur", "eigen", "pudgy", "linea", "zama", "zora", "tensor", "highlight", "manifold", "optimism"]);

/** ASCII look-alikes drainer kits use in hostnames: rn->m, vv->w, cl->d, 1->l, 0->o */
export function asciiSkeleton(s: string): string {
  return s.replace(/rn/g, "m").replace(/vv/g, "w").replace(/cl/g, "d").replace(/1/g, "l").replace(/0/g, "o");
}

/** "papertradefnd" -> "papertrade", "officialzama" -> "zama": clones glue affixes onto the real name. */
export function stripCloneAffixes(token: string): string {
  const AFFIX = ["foundation", "official", "finance", "protocol", "network", "testnet", "mainnet", "labs", "team", "dao", "fndn", "fnd", "fdn", "app", "xyz", "eth", "sol", "ico", "ido", "tge", "token", "coin", "portal", "claim", "drop", "net", "hq", "io"];
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

  // on the platform host itself (sites.google.com, docs.google.com) the labels name the platform, not a brand
  const allLabels = p.freeHost && p.host === p.freeHost ? [] : [...p.subLabels, p.domainLabel];
  const tokens = tokenize(allLabels);
  const strippedTokens = tokens.map(stripCloneAffixes);
  const joined = allLabels.join("").toLowerCase().replace(/[^a-z0-9]/g, "");
  const joinedSkeleton = asciiSkeleton(joined);

  // a bait word anywhere in the host, known before brand matching (short curated names like okx / gmx / cow only
  // count next to one, or on a free host: "gate-house-hotel" is a hotel, "okx-claim" is not)
  const earlyBait = tokens.some((t) => ctx.lists.actionStrong.includes(t) || ctx.lists.actionMedium.includes(t));

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
  // IDN homograph: "metаmask.io" with a Cyrillic а decodes to the brand's skeleton
  let homograph: string | null = null;
  if (!brandOfficial) {
    const skel = homographHost(p.host);
    if (skel && skel !== p.host) {
      const skelJoined = skel.split(".").slice(0, -1).join("").replace(/[^a-z0-9]/g, "");
      for (const b of ctx.brands) {
        if (b.tier === "generated") continue;
        for (const t of b.tokens) {
          const tok = t.toLowerCase();
          if (tok.length >= 5 && !GENERIC.has(tok) && skelJoined.includes(tok)) { homograph = b.name; matchedBrand = b; brandSignalKind = "typo"; break; }
        }
        if (homograph) break;
      }
    }
  }
  if (!brandOfficial && !matchedBrand) {
    outer: for (const b of ctx.brands) {
      if (b.tier === "generated") continue;
      for (const t of b.tokens) {
        const tok = t.toLowerCase();
        const generic = GENERIC.has(tok) || tok.length < 5;
        // Curated brands: substring match in the whole hostname (catches pancakeswapclaim6754).
        const substringOk = joined.includes(tok);
        if (!generic && substringOk) {
          matchedBrand = b;
          brandSignalKind = b.domains.length ? "impersonation" : "unverified";
          break outer;
        }
        // exact label match for short/generic tokens (catches blur-claim.xyz, not database.xyz)
        if (generic && tokens.includes(tok) && tokens.filter((x) => !HOST_NOISE.has(x)).length > 1 && (tok.length >= 5 || earlyBait || p.freeHost)) {
          matchedBrand = b;
          brandSignalKind = b.domains.length ? "impersonation" : "unverified";
          break outer;
        }
        // typosquat: one edit away from a distinctive *curated* brand token (unlswap, metamsk)
        if (tok.length >= 6 && tokens.some((x) => x !== tok && Math.abs(x.length - tok.length) <= 1 && levenshtein(x, tok) === 1)) {
          matchedBrand = b;
          brandSignalKind = "typo";
          break outer;
        }
        // visual look-alike spelled in ASCII (rnetamask, vvalletconnect, ledqer is covered by levenshtein)
        if (!generic && tok.length >= 6 && joinedSkeleton !== joined && joinedSkeleton.includes(tok)) {
          matchedBrand = b;
          brandSignalKind = "typo";
          break outer;
        }
      }
    }
  }

  if (!brandOfficial && !matchedBrand) {
    // auto-imported brands (DefiLlama / CMC / OpenSea): O(1) whole-token lookup, only after the curated list had
    // its chance, so "MetaMask Wallet" from a token list cannot shadow the curated MetaMask entry.
    const gi = generatedIndex(ctx.brands);
    for (const tk of [...tokens, ...strippedTokens]) {
      const b = gi.get(tk);
      if (b) { matchedBrand = b; brandSignalKind = b.domains.length ? "impersonation" : "unverified"; break; }
    }
  }

  const reviewedHit = !!ctx.blocklistHit && ctx.blocklistHit !== "phishdestroy" && ctx.blocklistHit !== "scamsniffer";
  if (brandOfficial && matchedBrand && !(matchedBrand.tier === "generated" && reviewedHit)) {
    // An auto-imported "official" domain (DefiLlama/CMC/OpenSea data) does not outrank a reviewed blocklist entry:
    // listed scam projects exist on those platforms. Curated seed/trusted entries still do.
    // Curated official domains relax the wallet gate; auto-imported ones only clear the heuristics (their data can
    // name shared hosts or a scam project's own site), so they carry a distinct id the gate does not treat as safe.
    signals.push({ id: matchedBrand.tier === "generated" ? "brand-official-generated" : "brand-official", weight: 0, key: "sig_brand_official", sub: [matchedBrand.name] });
    return done({ brand: matchedBrand.name });
  }
  if (ctx.allowlistHit) {
    signals.push({ id: "allowlist", weight: 0, key: "sig_allowlist" });
    return done();
  }

  // ---- hard block gate ----------------------------------------------------
  if (ctx.blocklistHit) {
    // MetaMask and our moderators' list are reviewed and block on their own. ScamSniffer and PhishDestroy are
    // broader (ScamSniffer carried bing.com and surveymonkey.com in 2026-10): alone they warn, and become a block
    // when a local heuristic agrees (the combination is added further down). auto = AI-confirmed but unseen by a
    // moderator: warn, never block. A top-50k site is never blocked by a single feed, whichever it is.
    // 60: alone it warns; with any corroborating signal (came from X, a bait word, a fresh registration) it blocks
    let weight = ctx.blocklistHit === "phishdestroy" || ctx.blocklistHit === "scamsniffer" ? 60 : ctx.blocklistHit === "community-auto" ? 40 : 100;
    if (ctx.popular && ctx.blocklistHit !== "metamask") weight = Math.min(weight, 50);
    signals.push({ id: "blocklist", weight, key: "sig_blocklist", sub: [ctx.blocklistHit] });
  }

  if (ctx.siblingHit && !ctx.blocklistHit) {
    // a listed neighbour on the same free host with a structurally similar label: strong hint, not proof
    signals.push({ id: "blocklist-sibling", weight: 25, key: "sig_blocklist_sibling", sub: [ctx.siblingHit] });
  }
  // deferred: the attacked-brand signal needs hasAction / freeHost / fresh, computed below

  const fresh = ctx.ageDays !== undefined && ctx.ageDays < 30;
  // Phishing domains live days, not years (avg 8.6 days; re-registrations get a new registration date).
  // A registrable domain older than a year that carries a brand name is brand sprawl (bybitglobal.com), not a clone.
  const old = ctx.ageDays !== undefined && ctx.ageDays > 365;

  // ---- hostname heuristics ---------------------------------------------------
  // bait words also count when glued into one label (checkeligibility, claimone, freemintclaim) and when the TLD
  // itself is the bait (.claims, .rewards); ordinary English words that merely contain one (disclaimer) do not
  const NOT_BAIT = new Set(["disclaimer", "disclaimers", "proclaim", "acclaim", "exclaim", "reclaimed", "unclaimed", "mintage", "peppermint", "spearmint", "badminton", "rewardsprogram"]);
  const plural = (t: string) => /s$/.test(t) && (ctx.lists.actionStrong.includes(t.slice(0, -1)) || ctx.lists.actionStrong.includes(t.replace(/es$/, "")));
  const glued = (t: string) => !NOT_BAIT.has(t) && (plural(t) || ctx.lists.actionStrong.some((a) => a.length >= 4 && t !== a && t.includes(a) && t.length - a.length >= 3));
  const strongActions = tokens.filter((t) => ctx.lists.actionStrong.includes(t) || glued(t));
  if (p.tld && ctx.lists.actionStrong.includes(p.tld)) strongActions.push(p.tld);
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
      if (strongActions.length || (mediumActions.length && (p.freeHost || fresh))) signals.push({ id: "brand-impersonation-weak", weight: 30, key: "sig_brand_impersonation", sub: [matchedBrand.name, matchedBrand.domains.slice(0, 2).join(", ")] });
      else brandFlagged = false;
    } else if (brandSignalKind === "typo" && homograph) {
      signals.push({ id: "idn-homograph", weight: 45, key: "sig_idn_homograph", sub: [matchedBrand.name] });
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
  // ...and the token must name something that exists: a known brand token, or one so widely phished (>=12 listed
  // roots) that it is a brand in practice. Ordinary words that happen to recur in feeds (admin, assets) never count.
  let attackedFlagged = false;
  // the token must be a known brand token (ordinary words recur in feeds too: "global", "finder", "bakery"), and it
  // must not be the very token that already produced a brand signal on this host (no double counting)
  // curated brands only (auto-imported token lists are full of ordinary words: global, digital, rocket, golden),
  // never a bait word, and never on a host that already produced a brand signal of any kind
  const attackedIsBrand = !!ctx.attacked && curatedTokenSet(ctx.brands).has(ctx.attacked.token) && !ctx.lists.actionStrong.includes(ctx.attacked.token) && !ctx.lists.actionMedium.includes(ctx.attacked.token);
  const sameAsBrand = !!matchedBrand;
  if (ctx.attacked && attackedIsBrand && !sameAsBrand && !ctx.blocklistHit && !ctx.siblingHit && (hasAction || p.freeHost || fresh || ctx.origin?.shortener)) {
    signals.push({ id: "attacked-brand", weight: 40, key: "sig_attacked_brand", sub: [ctx.attacked.token, String(ctx.attacked.count), ctx.attacked.example] });
    attackedFlagged = true;
  }

  // a shared platform page named after a brand: sites.google.com/view/metamask-support, github.io/<org>/uniswap-claim
  if (p.freeHost && !matchedBrand) {
    const path = (url.split("://")[1]?.slice(p.host.length) ?? "").split(/[?#]/)[0].toLowerCase();
    const pathTokens = tokenize(path.split("/").filter(Boolean).slice(0, 2));
    for (const b of ctx.brands) {
      if (b.tier === "generated") continue;
      const tok = b.tokens.find((t) => t.length >= 5 && !GENERIC.has(t.toLowerCase()) && pathTokens.some((x) => x === t.toLowerCase() || (x.length >= t.length + 3 && x.includes(t.toLowerCase()))));
      if (tok) {
        matchedBrand = b;
        brandFlagged = true;
        signals.push({ id: "brand-path", weight: hasAction || pathTokens.some((x) => ctx.lists.actionStrong.includes(x) || ctx.lists.actionMedium.includes(x)) ? 40 : 30, key: "sig_brand_path", sub: [b.name, "/" + path.split("/").filter(Boolean).slice(0, 2).join("/")] });
        break;
      }
    }
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
    // a search-ad click is only meaningful next to a brand or bait word (brand-keyword malvertising)
    if (o.source !== "ads" || hasAction || matchedBrand || ctx.attacked) {
      signals.push({ id: "origin-social", weight: 10, key: "sig_origin_social", sub: [SOURCE_LABEL[o.source]] });
    }
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
    // Not deception: the text shows a redirector (t.co, amzn.to, forms.gle...) or any host the link actually passed
    // through on its way here; only a domain that was never part of the chain is a lie.
    const disp = o.display?.toLowerCase();
    // The chain is only evidence when it ends where the user actually landed: a cloaker that showed our server (and
    // X's crawler) a decoy while sending the user elsewhere gets a signal of its own instead of a pass.
    const last = o.hops?.length ? o.hops[o.hops.length - 1] : undefined;
    const chainMatches = !!last && (isUnderDomain(p.host, last) || isUnderDomain(last, p.registrable));
    const inChain = !!disp && (isRedirector(disp) || (chainMatches && (o.hops ?? []).some((h) => h === disp || isUnderDomain(h, disp) || isUnderDomain(disp, h))));
    if (last && !chainMatches && !isRedirector(last)) signals.push({ id: "redirect-cloaked", weight: 20, key: "sig_redirect_cloaked", sub: [last] });
    if (disp && !inChain && disp !== p.host && !isUnderDomain(p.host, disp) && !isUnderDomain(disp, p.registrable)) {
      signals.push({ id: "display-mismatch", weight: 40, key: "sig_display_mismatch", sub: [o.display!] });
      // The card borrowed a real project's domain ("Kaynak: artblocks.io" -> qql-desk.com): impersonation by proxy.
      const borrowed = ctx.brands.find((b) => b.domains.some((d) => isUnderDomain(disp, d))) ?? (ctx.lists.trusted.some((d) => isUnderDomain(disp, d)) ? { name: disp } : undefined);
      if (borrowed) signals.push({ id: "display-brand-mismatch", weight: 25, key: "sig_display_brand_mismatch", sub: [borrowed.name] });
      // ...and hid the real destination behind a shortener: nothing legitimate needs both
      if (o.shortener) signals.push({ id: "display-shortener", weight: 15, key: "sig_display_shortener", sub: [o.shortener] });
    }
  }

  // ---- page links to a real project's X account while living elsewhere --------------
  // Clones paste the victim project's official X/Discord links in the footer to look legitimate.
  // Only on hosts that already look like bait (aggregators and news sites link to many projects).
  if (ctx.socials?.xHandles.length && ctx.handleIndex && (hasAction || p.freeHost || fresh || brandFlagged || attackedFlagged || !!o)) {
    let hit = false;
    // 1) exact: the handle is a listed project's official account
    for (const h of ctx.socials.xHandles.slice(0, 8)) {
      const b = ctx.handleIndex.get(h.toLowerCase());
      if (!b || !b.domains.length) continue;
      if (b.domains.some((d) => isUnderDomain(p.host, d))) continue; // it is the project's own site
      signals.push({ id: "page-official-x", weight: 35, key: "sig_page_official_x", sub: ["@" + h, b.name, b.domains[0]] });
      if (!matchedBrand) matchedBrand = b;
      brandFlagged = true;
      hit = true;
      break;
    }
    // 2) by name: @ETHGasFNDN -> "ethgas" -> the ETHGas brand (projects run several accounts; lists hold one)
    if (!hit && ctx.brandByToken) {
      for (const h of ctx.socials.xHandles.slice(0, 8)) {
        const stem = stripCloneAffixes(h.toLowerCase().replace(/[^a-z0-9]/g, ""));
        if (stem.length < 5) continue;
        const b = ctx.brandByToken.get(stem);
        if (!b || !b.domains.length || b.domains.some((d) => isUnderDomain(p.host, d))) continue;
        signals.push({ id: "page-brand-x", weight: 25, key: "sig_page_official_x", sub: ["@" + h, b.name, b.domains[0]] });
        if (!matchedBrand) matchedBrand = b;
        brandFlagged = true;
        break;
      }
    }
  }
  // 3) verified at runtime (Xquik): the linked account is a real, sizeable account whose bio points elsewhere
  if (ctx.socials?.verified && (hasAction || p.freeHost || fresh || brandFlagged || attackedFlagged || !!o)) {
    const vx = ctx.socials.verified;
    if (vx.domains.length && !vx.domains.some((d) => isUnderDomain(p.host, d)) && !signals.some((s) => s.id === "page-official-x")) {
      signals.push({ id: "page-official-x", weight: 35, key: "sig_page_official_x", sub: ["@" + vx.handle, vx.name || vx.handle, vx.domains[0]] });
      brandFlagged = true;
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
      // Official accounts get hijacked and their bio swapped (ArbitrumDAO 2026): this clears, but never a
      // freshly registered domain, and never below what a reviewed blocklist hit says.
      // "not fresh" must be a known fact: with the registry unreachable an account named after the token, with
      // bought followers and a bio link, could otherwise clear the page it was made for.
      const ageKnown = ctx.ageDays !== undefined && ctx.ageDays >= 30;
      if (ageKnown && !ctx.blocklistHit && xi.confidence >= 0.7) {
        signals.push({ id: "x-domain-match", weight: -45, key: "sig_x_domain_match", sub: ["@" + off.handle] });
        xCleared = true;
      }
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
  if (ctx.popular && ctx.blocklistHit !== "metamask" && v.score >= BLOCK_THRESHOLD) {
    // from the raw sum, not the clamped score: a sum of 140 must land on 69 too
    const raw = signals.reduce((s, x) => s + x.weight, 0);
    signals.push({ id: "popular", weight: BLOCK_THRESHOLD - 1 - raw, key: "sig_popular" });
    return done({ brand: matchedBrand?.name, ageDays: ctx.ageDays });
  }

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
