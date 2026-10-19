# Web3 Phish Guard — analysis sandbox

A small server that opens a suspicious page in a throw-away headless browser, records every request the page
makes to a wallet, simulates the transaction-shaped ones, and returns a verdict. It is the server-side version of
the extension's deep analysis: the user clicks **Deep analysis**, the extension asks the Cloudflare Worker, and the
Worker asks this service. The user's own wallet is never involved.

## How it works

1. A fresh, isolated browser context is created for each scan (no cookies, no real wallet).
2. Before the page loads, an **observer provider** is injected. It answers read-only calls (so the page's flow
   proceeds) but **never signs or sends anything**: every transaction or signature request is recorded and then
   rejected with error 4001, exactly as a user clicking "Reject" would. The address it exposes is a random, empty,
   throw-away address.
3. The harness lightly nudges the page (clicks obvious *Connect / Claim / Mint* buttons) so a drain-on-connect
   page reveals itself.
4. Each recorded transaction is replayed through `eth_simulateV1` on a free public RPC to see what signing it
   *would* have done ("USDC leaves the wallet, nothing comes back", "unlimited approval to 0x…").
5. Page scripts are matched against known drainer-kit fingerprints, outbound hosts against a known-bad list, and
   the DOM is checked for seed-phrase / private-key inputs.
6. A score (0–100) and a verdict (`malicious` / `suspicious` / `clean`) plus short findings are returned.

Nothing here impersonates a specific wallet brand, produces a signature, or holds a private key.

## Run locally

```bash
cd sandbox
npm install            # also downloads Chromium
cp .env.example .env   # set SANDBOX_TOKEN
npm run build
SANDBOX_TOKEN=$(grep -oP '(?<=SANDBOX_TOKEN=).*' .env) node dist/server.js
# smoke test (serves test/trap.html and scans it)
node test/smoke.mjs
```

## Deploy on a VPS

2 vCPU / 4 GB is plenty for `MAX_CONCURRENT=3`.

### Docker (recommended)

```bash
docker build -t w3pg-sandbox ./sandbox
docker run -d --name w3pg-sandbox -p 127.0.0.1:8080:8080 \
  -e SANDBOX_TOKEN='a-long-random-string' \
  --restart unless-stopped w3pg-sandbox
```

Put it behind nginx/Caddy with TLS and only expose HTTPS. The service listens on `127.0.0.1` in the example so
only the reverse proxy reaches it.

### Bare Node

```bash
cd sandbox && npm ci && npx playwright install --with-deps chromium && npm run build
SANDBOX_TOKEN='a-long-random-string' PORT=8080 node dist/server.js   # under systemd/pm2
```

## Wire it to the Worker

The extension only ever talks to the Worker. Point the Worker at this service with two secrets:

```bash
cd ../backend
npx wrangler secret put SANDBOX_URL     # e.g. https://sandbox.yourdomain.com
npx wrangler secret put SANDBOX_TOKEN   # the same token as above
```

With those unset, `/v1/sandbox` returns `503 sandbox_disabled` and the extension simply omits the sandbox block.

Optional Worker vars (budgets, protect the VPS): `SANDBOX_PER_IP_PER_DAY` (default 10), `SANDBOX_GLOBAL_PER_DAY`
(default 500).

## API

`POST /scan` — header `Authorization: Bearer <SANDBOX_TOKEN>`, body `{ "url": "https://…" }`. Returns the scan
report (see `src/types.ts`). `GET /health` for liveness.

## Safety

- The target URL must be a public http(s) host; localhost, private, loopback and link-local addresses are refused
  (basic SSRF guard — run the container on an isolated network for defence in depth; DNS-rebinding to a private
  target is not fully mitigated here).
- The browser runs with `--no-sandbox` inside the container; keep the container unprivileged and network-isolated.
- Scans are rate-limited and time-boxed. One shared browser, bounded concurrency.
