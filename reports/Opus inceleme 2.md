# Opus independent review 2 (2026-10-19)

Not committed on purpose: this repo is public and the findings below describe unfixed weaknesses.

## CRITICAL

### C1. Feed entries for shared platforms block whole platforms (happening now)
- src/lib/blocklist.ts:236 (generic extractDomains), :254-258 (refreshMetaMaskDiffs), :207-213 (normalizeDomain strips the path).
- ScamSniffer domains.json contains bare `sites.google.com`, `storage.googleapis.com`, `r2.dev`. blocklistHit() matches parent domains, so every Google Sites / GCS / r2.dev page scores 100 with the two-click "reviewed" warning.
- MetaMask diffs carry `targetList: "eth_phishing_detect_config.blocklistPaths"` (130 path entries live). `target.includes("blocklist")` accepts them and normalizeDomain cuts the path, so `sites.google.com` itself lands in the MetaMask set. Both feeds also go into DNR main_frame rules. Real path-level coverage (stalelist blocklistPaths, 521 entries) is never imported.
- Fix: drop feed entries that are free hosts / public suffixes / PSL private suffixes; only accept `targetList === "eth_phishing_detect_config.blocklist"` as hosts; import blocklistPaths into a host+path-prefix matcher with DNR urlFilter rules; regression tests from live payload shapes.

### C2. Anyone can get any domain blocked network-wide via /v1/scan auto-listing
- backend/src/index.ts:382 (client-supplied origin fed into server score), :435-446 (auto-list), wrangler.toml ALLOWED_ORIGINS="".
- Forged payload `origin:{source:"x", display:"uniswap.org"}` gives origin-social 10 + display-mismatch 40 = 50 >= 35 floor. Snapshot is attacker-written (fake seed inputs, drainer markers), Haiku says dangerous >= 0.9. Only trusted/brand-official excluded; MetaMask allowlist not checked server-side. Domain lands in `auto`; extensions weight community-auto 70 and DNR-block it after next refresh. One request per victim domain.
- Fix: never let client origin/x context count toward auto-list score; require server-side page fetch or N independent reporters or known-fresh domain (<30d); make `auto` warn-only (weight 40, no DNR) until human confirm; top-N Tranco "never block" guard server and client.

## HIGH

### H1. Generated brand entries shadow curated brands
- src/lib/scoring.ts:141-148: generated-tier O(1) lookup runs before the curated loop and claims the match.
- Measured score 0: metamask-io.com, uniswap-labs.net, pancakeswap-v3.app, opensea-pro.xyz, uniswap.foundation-app.com. uniswap-airdrop.com only weak 30. poster-mismatch lost (generated entries have no x).
- test/scoring.test.ts:10 only loads brands.seed.json.
- Fix: curated/seed match first (or seed wins); tests loading generated, CMC and NFT data.

### H2. Shared hosting counts as official/trusted, which turns the gate off
- Generated brand data lists eth.limo (7 brands), eth.link, substack.com as official domains (builder reduces x.eth.limo to registrable). `uniswap-airdrop-claim.eth.limo`, `claim.substack.com` score 0 as brand-official.
- trusted.json includes pinata.cloud so gateway.pinata.cloud/ipfs/<cid> is trusted.
- On safeSite gateDecision (background.ts:648-651) skips unlimited approve / setApprovalForAll / Permit; provider events capped at 30 (:460-464) so ClickFix and seed entry never reach warn band. eth.limo, eth.link, mypinata.cloud not in free-hosts.json.
- Fix: keep full hostname for brand domains under shared parents; shared-parent denylist in all three builders (SHARED sets are inconsistent); remove pinata.cloud from trusted; add IPFS/ENS gateways to free hosts; generated-tier official must not count as safeSite for gating.

### H3. MAIN-world wallet gate bypassable from page JS
- provider-guard.ts:119-128: `request` overridden on instance only; `Object.getPrototypeOf(ethereum).request.call(ethereum, ...)`, `_rpcRequest`, prototype `send` skip it.
- :28-34: page can post `{source:"w3pg-ext", type:"gate-result", id, allow:true}` itself (e.source === window passes).
- :38: 90 s timer not cleared while modal open -> fail-open; page removing #w3pg-gate gets the same; gate inside 1x1 iframe shows invisible modal.
- Fix: MessageChannel port from bridge to guard at document_start kept in a closure; patch prototypes or Proxy from window.ethereum getter; fail closed for always-hold kinds (no timeout while displayed, re-render if removed); raise modal in top frame; document that the gate stops off-the-shelf kits.

### H4. Supply chain: signing scope too narrow, pipeline soft
- lists.ts:119-124 caps only trusted.json; a signed remote brands.seed.json can add any domain as seed-tier official (beats MetaMask/ScamSniffer hits, scoring.ts:179).
- Community lists fetched raw without manifest hash (blocklist.ts:22-24).
- refresh workflow: npm install without lockfile, scripts enabled, tag-pinned actions, persist-credentials default, signing in same job.
- upstream workflow runs MetaMask's yarn install + test:config with ADMIN_TOKEN and MM_PR_TOKEN in env.
- Fix: cap/diff all allowlisting fields; verify community lists against manifest; lockfile + `npm ci --ignore-scripts`, SHA-pinned actions, persist-credentials false; sign in separate minimal job; run third-party code with --ignore-scripts in a step without secrets; read-only token for export.

### H5. Report / admin-add / auto-list collapse Google Sites, S3, Fleek to parent
- backend/src/index.ts:189-196: tldParse(allowPrivateDomains:false) turns x.sites.google.com -> google.com, bucket.s3.amazonaws.com -> amazonaws.com, ipfs.fleek.co -> fleek.co; free-host check compares the collapsed domain and misses.
- One approved Google Sites report blocks google.com for everyone; upstream job would submit it.
- Fix: match free hosts against the full host first (like client parseHost); refuse registrable domains on a top-sites guard list.

### H6. Seed guard false positives on tx hashes and Solana signatures
- seed-guard.ts:174-182: 0x+64 hex (tx hash) and 88-char Solana signature return "private-key". Pasting a tx hash on etherscan/solscan triggers full-screen stop and +60 (capped 30 on trusted).
- "Stay" (:239) resets fired so the next keystroke re-triggers; mnemonic UIs (MEW-style) unusable.
- Fix: 0x+64 hex weak unless label says private key; require key context for 86-90 char base58; skip trusted/official hosts; keep stay suppression for page lifetime.

## MEDIUM

### M1. Cross-origin iframes blind spot
- Provider events from other-host frames dropped (background.ts:459); gate uses top-frame verdict for iframe requests (:508); DNR main_frame only (dnr.ts:27,35); seed-guard and page-scan top frame only (manifest.json:71-82).
- Fix: evaluate frame's own host for gate/provider events, max with top; add sub_frame to DNR; seed-guard all frames.

### M2. Backend budget and abuse
- CORS reflects any origin (live: ACAO https://evil.example on preflight /v1/scan): any website can spend scans/Xquik credits from visitors' IPs.
- Firefox moz-extension origins random per install -> ALLOWED_ORIGINS cannot fix; need signed client token or proof-of-work.
- IPv6 keyed per full address; bucket by /64.
- SCANS_PER_HOST_PER_DAY lets a phisher burn 30 scans on their own host so real users get host_capacity_reached.
- KV allow() non-atomic; scan:global written on every scan vs KV 1 write/s/key -> 500s.
- community:list and reports:pending lost updates; Durable Object or D1.
- Queue at 2000 silently drops new reports (index.ts:459).

### M3. Privacy and store-compliance accuracy
- ext_description "All checks run locally" false: RDAP, hostname tokens, X handles, short links leave the browser automatically. README privacy section outdated.
- Deep scan sends v.url with query string (deepscan.ts:119); PRIVACY.md silent.
- Auto-list stores payload.url with query for 90 days (index.ts:442); PRIVACY.md says without query.
- ipKey uses ADMIN_TOKEN as HMAC key (index.ts:84): IPv4 brute-forceable by token holder; use a dedicated secret.
- Firefox manifest data_collection_permissions.required ["none"] while sending browsing-derived data: AMO rejection risk; declare websiteActivity or opt-in.
- Chrome listing privacy tab must declare web history and website content.
- Firefox permissions.request from background on runtime message (background.ts:223-236) needs user-input handler; deep scan likely always permission_denied on Firefox. Move into popup click handler.

### M4. Alarms only in onInstalled (background.ts:26-31); Firefox clears on restart. Recreate in onStartup and ensureReady.

### M5. Clipboard / ClickFix guard
- provider-guard.ts:234-238 copy-event clipboardData.getData read in setTimeout after dispatch: never fires.
- :221 writeText wrapped on instance; Clipboard.prototype.writeText.call bypasses; clipboard.write not covered.
- ClickFix on safe sites capped 30, no modal.
- Fix: sync read in bubble-phase window listener; patch Clipboard.prototype; own stop UI for ClickFix.

### M6. Decoder and coverage gaps (txdecode.ts)
- EIP-3009 TransferWithAuthorization / ReceiveWithAuthorization (USDC) decode to "other", allowed silently.
- Missing selectors: ERC-1155 safeTransferFrom 0xf242432a, safeBatchTransferFrom 0x2eb2c2d6; Universal Router execute with PERMIT2_* commands; Multicall3 aggregate*; Safe multiSend.
- 7702-delegated EOAs return 0xef0100... code so isEoa treats drainer spenders as contracts (provider-guard.ts:62).
- Seaport and Blur orders not in alwaysHold.
- solana.request({method:"signAndSendTransaction"}) not wrapped.
- MetaMask Multichain API (CAIP-25 over externally_connectable) and Wallet Standard bypass window.ethereum.
- Address poisoning only remembers recipients from current page.

### M7. X official-account clear (-45) fires when domain age unknown (scoring.ts:385). Require known age > 30d and higher confidence.

### M8. Fake Chrome Web Store listing check (background.ts:298-326) only on onCommitted (store is SPA; add onHistoryStateUpdated); regexes too coarse (MetaMask Flask, rainbow/argent/coinbase tools get 75-point block).

### M9. Service-worker cost and storage growth
- ~600k domains as JS Sets; raw feeds ScamSniffer 9.1 MB, PhishDestroy 3.7 MB, MetaMask 2.5 MB re-read and re-Set on every MV3 wake.
- list:metamask (~3 MB) rewritten every 5 min when diffs exist.
- DNR session rules fully rebuilt on every cold start.
- storage.session warn:*, deep:*, origin:*, soc:*, pev:* never removed (10 MB quota); when set() throws verdicts stop silently.
- Fix: compact/persisted index (sorted hashes or IndexedDB); skip DNR rebuild when unchanged; cleanup per tab onRemoved + TTL sweep.

### M10. Fingerprintable: warning.html web-accessible for <all_urls> (manifest.json:84-93) not needed (tabs.update doesn't require it). Remove or use_dynamic_url. window.ethereum getter detectable too.

## LOW
- L1. First-pass applyVerdict not guarded by stillOn; late provider events from previous document merge into new page (background.ts:164, 455).
- L2. ledger and phantom in GENERIC only exact-label: ledgerlive-update.com scores 20, rnetamask.io 0. No ASCII visual typos (rn->m, vv->w).
- L3. Free-host list missing: eth.limo, eth.link, storage.googleapis.com, firebasestorage.googleapis.com, trycloudflare.com, ngrok-free.app, csb.app, gamma.app, canva.site, wixstudio.com, myshopify.com, telegra.ph, mypinata.cloud, 4everland.app, docs.google.com.
- L4. Seed guard: shadow DOM inputs not read (composedPath); English wordlist only; 250 ms debounce after keystroke-exfil; paste could be blocked synchronously in capture listener.
- L5. refreshRemoteData(force) accepts an older signed manifest (rollback).
- L6. scanExternalScripts fetches page-chosen URLs from extension context; IP regex doesn't cover internal hostnames.
- L7. Upstream PR body publishes free-text moderator notes.
- L8. Warning nonce reusable 30 min though comment says one-shot.
- L9. Popup renders negative weights as "(+-45)" (popup.ts:20).
- L10. README contradictions: "no request is blocked", "code stays private", outdated privacy section.
- L11. AMO reproducibility: brands.generated/cmc/nft gitignored; minified bundles.
- L12. Missing Vary: Origin on reflected-ACAO cacheable responses.
- L13. `tabs` permission probably unnecessary.

## Tests worth adding
Scoring against full generated/CMC/NFT data (H1); feed ingestion with shared-host entries and blocklistPaths diffs (C1); backend registrableOf and auto-list rules (C2, H5); seed guard with tx hashes/signatures (H6); gateDecision and providerWeight incl. iframe/safe-site; verifyManifest with tampered seed file; bridge/guard message spoofing in jsdom.

## Checked and found fine
Message auth; warning page nonce flow; admin auth and escaping; AI endpoint (no path to misuse the key); /v1/resolve SSRF limited; manifest signature logic; IDN; decoding of covered selectors; i18n complete; packaging; no secrets in repo; trusted gate overriding feed mistakes; Firefox build.
