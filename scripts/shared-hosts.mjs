// Hosts that can never be a project's "official domain": shared platforms, link pages, marketplaces, social sites.
// A brand whose only site lives on one of these stays "unverified" (no official domain), which keeps a scam page on
// the same platform from inheriting the brand's clearance. Used by all three brand builders.
import { readFileSync } from "node:fs";

const freeHosts = JSON.parse(readFileSync("data/free-hosts.json", "utf8"));
const sharedFile = JSON.parse(readFileSync("data/shared-hosts.json", "utf8"));
export const SHARED_HOSTS = new Set([
  ...freeHosts.strong, ...freeHosts.weak, ...sharedFile.hosts,
  // ENS / IPFS gateways and shared storage
  "eth.limo", "eth.link", "ipfs.io", "dweb.link", "w3s.link", "nftstorage.link", "mypinata.cloud", "pinata.cloud", "4everland.app", "fleek.co", "on-fleek.app", "arweave.net", "ar-io.dev",
  // social / link pages / docs
  "x.com", "twitter.com", "github.com", "gitlab.com", "t.me", "telegram.org", "medium.com", "youtube.com", "google.com", "docs.google.com", "sites.google.com", "play.google.com", "apple.com", "discord.gg", "discord.com", "linktr.ee", "notion.site", "notion.so", "gitbook.io", "substack.com", "mirror.xyz", "paragraph.xyz", "instagram.com", "tiktok.com", "facebook.com", "reddit.com", "linkedin.com", "warpcast.com", "farcaster.xyz", "lens.xyz",
  // marketplaces, launchpads, explorers and aggregators that host many projects' pages
  "coinmarketcap.com", "coingecko.com", "pump.fun", "etherscan.io", "bscscan.com", "solscan.io", "basescan.org", "arbiscan.io", "dexscreener.com", "dextools.io", "uniswap.org", "raydium.io", "opensea.io", "magiceden.io", "blur.io", "zora.co", "manifold.xyz", "highlight.xyz", "rarible.com", "foundation.app", "superrare.com", "objkt.com", "tensor.trade", "jup.ag", "dexlab.space",
]);

export function isSharedHost(domainOrHost) {
  const d = String(domainOrHost || "").toLowerCase();
  for (const sh of SHARED_HOSTS) if (d === sh || d.endsWith("." + sh)) return true;
  return false;
}
