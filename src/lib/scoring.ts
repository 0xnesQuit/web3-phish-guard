import type { Band, Brand, ParsedHost, Signal, SignalLists, Verdict } from "./types";
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
}

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
    signals.push({ id: "user-allow", weight: 0, label: "Kullanıcı bu domaini güvenilir işaretledi" });
    return done();
  }
  if (p.isIp) {
    signals.push({ id: "ip-host", weight: 10, label: "Alan adı yerine IP adresi" });
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
        // substring match in the whole hostname (catches pancakeswapclaim6754)
        if (!generic && joined.includes(tok)) {
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
    signals.push({ id: "brand-official", weight: 0, label: `${matchedBrand.name} resmi alan adı` });
    return done({ brand: matchedBrand.name });
  }
  if (ctx.allowlistHit) {
    signals.push({ id: "allowlist", weight: 0, label: "Bilinen güvenli liste (MetaMask allowlist)" });
    return done();
  }

  // ---- hard block gate ----------------------------------------------------
  if (ctx.blocklistHit) {
    signals.push({ id: "blocklist", weight: 100, label: `Bilinen phishing listesinde (${ctx.blocklistHit})` });
  }

  // ---- hostname heuristics ---------------------------------------------------
  const strongActions = tokens.filter((t) => ctx.lists.actionStrong.includes(t));
  const mediumActions = tokens.filter((t) => ctx.lists.actionMedium.includes(t));
  const hasAction = strongActions.length > 0 || mediumActions.length > 0;

  if (strongActions.length) {
    signals.push({ id: "action-strong", weight: Math.min(30, 20 + (strongActions.length - 1) * 5), label: `Alan adında "${[...new Set(strongActions)].join(", ")}" gibi tuzak kelimeler` });
  } else if (mediumActions.length) {
    signals.push({ id: "action-medium", weight: 10, label: `Alan adında "${[...new Set(mediumActions)].join(", ")}" kelimesi` });
  }

  if (p.freeHost) {
    const strong = ctx.lists.freeHostsStrong.includes(p.freeHost);
    signals.push({ id: "free-host", weight: strong ? 20 : 8, label: `Ücretsiz/paylaşımlı barındırma (${p.freeHost})` });
  } else if (p.tld) {
    const tldLast = p.tld.split(".").pop() ?? p.tld;
    if (ctx.lists.tldStrong.includes(tldLast)) signals.push({ id: "tld-strong", weight: 15, label: `Yoğun kötüye kullanılan uzantı (.${tldLast})` });
    else if (ctx.lists.tldWeak.includes(tldLast)) signals.push({ id: "tld-weak", weight: 5, label: `Sık kötüye kullanılan uzantı (.${tldLast})` });
  }

  if (matchedBrand && brandSignalKind && brandSignalKind !== "official") {
    if (brandSignalKind === "impersonation" && matchedBrand.tier !== "generated") {
      signals.push({ id: "brand-impersonation", weight: 40, label: `"${matchedBrand.name}" adını taşıyor ama resmi alan adı değil (${matchedBrand.domains.slice(0, 2).join(", ")})` });
    } else if (brandSignalKind === "impersonation") {
      // auto-imported brand: names are often common words and domains drift (kamino.finance vs kamino.com),
      // so it only counts alongside an action word or free hosting
      if (hasAction || p.freeHost) signals.push({ id: "brand-impersonation-weak", weight: 30, label: `"${matchedBrand.name}" adını taşıyor ama bilinen alan adı değil (${matchedBrand.domains.slice(0, 2).join(", ")})` });
    } else if (brandSignalKind === "typo") {
      signals.push({ id: "brand-typo", weight: 35, label: `"${matchedBrand.name}" adının bir harf farklı taklidi` });
    } else if (hasAction || p.freeHost) {
      // brand with unverified official domain only counts together with another signal
      signals.push({ id: "brand-unverified", weight: 25, label: `"${matchedBrand.name}" proje adını taşıyor; resmi alan adı henüz doğrulanmadı` });
    }
  }

  // digits glued to words: pancakeswapclaim6754, claim-arb2
  if (/[a-z]\d{2,}/.test(p.domainLabel.replace(/-/g, "")) && (hasAction || matchedBrand)) {
    signals.push({ id: "digits", weight: 10, label: "Kelimelere yapıştırılmış rakamlar" });
  }

  // "rewards-<something>" style even when the brand is unknown to us
  if (!matchedBrand && hasAction && /-/.test(p.domainLabel) && tokens.length >= 2) {
    signals.push({ id: "action-hyphen", weight: 10, label: "Tuzak kelime + proje adı kalıbı (ör. claim-proje)" });
  }

  if (p.subLabels.length >= 3 || p.host.length > 40) {
    signals.push({ id: "long-host", weight: 5, label: "Olağandışı uzun alan adı" });
  }

  // ---- domain age -----------------------------------------------------------
  if (ctx.ageDays !== undefined) {
    if (ctx.ageDays < 7) signals.push({ id: "age-7", weight: 25, label: `Alan adı ${Math.max(0, Math.floor(ctx.ageDays))} gün önce kaydedilmiş` });
    else if (ctx.ageDays < 30) signals.push({ id: "age-30", weight: 15, label: `Alan adı ${Math.floor(ctx.ageDays)} gün önce kaydedilmiş` });
    else if (ctx.ageDays < 90) signals.push({ id: "age-90", weight: 5, label: `Alan adı ${Math.floor(ctx.ageDays)} gün önce kaydedilmiş` });
    else if (ctx.ageDays > 365 * 2) signals.push({ id: "age-old", weight: -10, label: `Alan adı ${Math.floor(ctx.ageDays / 365)} yıldır kayıtlı` });
  }

  const v = done({ brand: matchedBrand?.name, ageDays: ctx.ageDays });

  // Combination rule from the research: brand + action word + (free host | fresh domain) is near-certain.
  if (matchedBrand && hasAction && (p.freeHost || (ctx.ageDays !== undefined && ctx.ageDays < 30))) {
    if (v.score < BLOCK_THRESHOLD) {
      signals.push({ id: "combo", weight: BLOCK_THRESHOLD - v.score, label: "Marka + tuzak kelime + yeni/paylaşımlı barındırma kombinasyonu" });
      return done({ brand: matchedBrand.name, ageDays: ctx.ageDays });
    }
  }

  // Age lookup is worth doing only when it could move the band.
  v.needsAgeCheck = ctx.ageDays === undefined && !ctx.blocklistHit && !p.freeHost && v.score >= 20 && v.score < BLOCK_THRESHOLD;
  return v;
}
