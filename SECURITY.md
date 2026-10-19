# Security policy

Web3 Phish Guard protects people from wallet drainers, so bugs in it matter. Please report
vulnerabilities privately rather than in a public issue:

- GitHub: use **Report a vulnerability** on this repository (Security tab), or
- open a GitHub issue that only says "security, please contact me" and we will reach out.

Please include the affected component (extension, lists repository, Cloudflare Worker), steps to
reproduce, and the impact you see. Do not test against the production API with real users' data.

## What is in scope

- Ways to make the extension miss a phishing page it should catch, or to disable its wallet-request gate from page JavaScript.
- Ways to make a legitimate site look like phishing at scale (list poisoning, signature bypass of the remote lists).
- Any route to the API's keys or to using the AI endpoint for anything but page verdicts.
- Bypasses of the admin panel's authentication or rate limits.

## Known limits of the wallet gate

The gate hooks the provider objects a page can reach (`window.ethereum`, EIP-6963 announcements, `window.solana`,
Wallet Standard registrations). A page that talks to a wallet by other means, for example by posting to the wallet's own
content-script message stream, or a wallet built into the page itself, is outside what an in-page hook can see. The
first line of defence is the warning before the page loads; the gate is the second, aimed at off-the-shelf drainer kits.

## What we do not consider a vulnerability

- The extension warning on a site that the heuristics score as risky (report it as a false positive instead; the warning can be bypassed and the site trusted).
- Rate limits being reachable by a single heavy user; they exist to protect the shared budget.
