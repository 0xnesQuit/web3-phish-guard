# Web3 Phish Guard – Privacy Policy

_Last updated: 2026-10-18_

Web3 Phish Guard is a browser extension that warns you when a page looks like a crypto phishing site (fake NFT mints, fake airdrop claims, wallet drainers). This policy explains exactly what data the extension processes and where it goes.

## What stays on your device

Every page you open is evaluated **locally in your browser**: the hostname is checked against phishing lists, brand lists and heuristics that are stored inside the extension. The URLs you visit are never sent to us or to anyone else for this check, and they are not logged.

## What leaves your device, and when

1. **List updates** (automatic, every 12 hours): the extension downloads updated phishing and brand lists from GitHub (`raw.githubusercontent.com`). These requests contain no information about your browsing.
2. **Domain age lookup** (automatic, only for suspicious pages): when the local score is in the "undecided" range, the extension asks the domain registry's public RDAP service for the registration date of the **domain name only** (for example `example.xyz`). No path, query string, or page content is sent.
3. **Link shortener resolution** (automatic, only on x.com): shortened links (t.co, tr.ee, bit.ly…) seen in your timeline are resolved to find their real destination so they can be scored before you click.
4. **X account check** (automatic, only for suspicious pages): the extension sends the project name found in the hostname, or an X handle linked from the page, to our server, which looks up the account through the Xquik API. Never the page URL.
5. **Deep scan** (only when you press the "Deep scan" button): a snapshot of the current page (title, a text sample, script file names, link domains, wallet-related buttons) together with the extension's findings is sent to our server, which asks an AI model (Anthropic Claude) for a verdict. The server independently checks the domain's registration age (RDAP), the MetaMask blocklist and the free GoPlus Security API, keeps the result cached for one hour keyed by a hash of the snapshot, and does not store the page text.
6. **Reports** (only when you press "Report this site"): the page URL, the extension's score and your optional note are sent to our server, where a human reviews them. Approved domains are added to a public blocklist. Reports are stored with the page address but without the query string. For abuse prevention we store a keyed hash of your IP address that changes every day and cannot be reversed; it is deleted with the report after 90 days.

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
