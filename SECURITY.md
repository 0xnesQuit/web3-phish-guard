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

## What we do not consider a vulnerability

- The extension warning on a site that the heuristics score as risky (report it as a false positive instead; the warning can be bypassed and the site trusted).
- Rate limits being reachable by a single heavy user; they exist to protect the shared budget.
