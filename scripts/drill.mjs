/** Serves test-dapp/ on http://127.0.0.1:8787 so the wallet gate can be exercised against a real wallet. */
import { createServer } from "node:http";
import { readFileSync } from "node:fs";
const html = readFileSync("test-dapp/index.html");
createServer((req, res) => { res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" }); res.end(html); }).listen(8787, "127.0.0.1", () => {
  console.log("drill page: http://127.0.0.1:8787/            (clean page: only the always-held requests are asked)");
  console.log("            http://127.0.0.1:8787/#w3pg-drill=45  (page pretends to score 45: score-dependent requests are asked too)");
  console.log("            http://127.0.0.1:8787/#w3pg-drill=75  (page pretends to score 75: warning page before load, bypass it, then test)");
});
