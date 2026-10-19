# Web3 Phish Guard – Privacy Policy

_Last updated: 2026-10-19_

Web3 Phish Guard is a browser extension that warns you when a page looks like a crypto phishing site (fake NFT mints, fake airdrop claims, wallet drainers). This policy explains exactly what data the extension processes and where it goes.

## What stays on your device

Every page you open is evaluated **locally in your browser** first: the hostname is checked against phishing lists, brand lists and heuristics that are stored inside the extension. The full URLs you visit are never sent to us or to anyone else for this check, and they are not logged. Some follow-up checks do contact servers, and each of them is listed below with exactly what leaves the browser.

## What leaves your device, and when

1. **List updates** (automatic, every 12 hours): the extension downloads updated phishing and brand lists from GitHub (`raw.githubusercontent.com`). These requests contain no information about your browsing.
2. **Domain age lookup** (automatic, only for suspicious pages): when the local score is in the "undecided" range, the extension asks the domain registry's public RDAP service (found through IANA's bootstrap file) for the registration date of the **domain name only** (for example `example.xyz`). This also applies to links visible in your X timeline whose score is undecided, before you click them. The registry therefore learns that someone using the extension looked up that domain. No path, query string, or page content is sent.
3. **Link shortener resolution** (automatic, only on x.com): shortened links (t.co, tr.ee, bit.ly…) that are visible in your timeline are sent to our server, which follows the redirect from its own address and returns the destination and the hosts passed on the way, so the link can be scored before you click. Your browser does not contact the destination. If our server is unreachable the extension follows the redirect itself, in which case the shortener and the destination see an anonymous request from your browser (no cookies).
4. **X account check** (automatic, only for suspicious pages): the extension sends the project name found in the hostname, the handle of the X account whose post carried the link, or an X handle linked from the page, to our server, which looks up the account through the Xquik API. Never the page URL.
5. **Deep scan** (only when you press the "Deep scan" button): the page address **without its query string**, a snapshot of the current page (title, a text sample, script file names, link domains, wallet-related buttons) and the extension's findings are sent to our server, which asks an AI model (Anthropic Claude) for a verdict. The server independently checks the domain's registration age (RDAP), the MetaMask blocklist and the free GoPlus Security API, keeps the result cached for one hour keyed by a hash of the snapshot, and does not store the page text. If the server's own checks and the model both find the page dangerous, the server fetches the page itself to confirm, and the domain (or, for pages on shared hosting, the full hostname; never a path or query string) may be added to a "warn-only" community list that a moderator reviews, together with the page address without its query string for that review.
6. **Reports** (only when you press "Report this site"): the page address without its query string, the extension's score and your optional note are sent to our server, where a human reviews them. Approved domains are added to a public blocklist. For abuse prevention the server stores a keyed hash of your IP address that changes every day (IPv6 addresses are first truncated to their /64 prefix); only the holder of the server's secret key could relate it to an address, and it is deleted with the report after 90 days.

In the Chrome Web Store's terms these checks use **web history** (the hostnames of suspicious pages) and, for deep scan only, **website content**. In Firefox's data-collection terms the extension declares **websiteActivity** as required and **websiteContent** (deep scan) as optional.

## What we never do

- We do not sell data, show ads, or share data with third parties beyond the services named above, each used only for the stated purpose.
- We do not collect wallet addresses, seed phrases, private keys, form inputs, cookies, or browsing history.
- The AI API key is stored only on our server; the extension cannot be used to access it.

## Your controls

- Deep scan and reporting are manual actions; nothing is sent until you press the button.
- You can mark any domain as trusted or remove it again in the settings.
- Uninstalling the extension removes all locally stored data.

## Contact

Open an issue at https://github.com/0xnesQuit/web3-phish-guard-lists or write to the address on the store listing.
