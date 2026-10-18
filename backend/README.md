# Web3 Phish Guard API (Cloudflare Worker)

Uzantının "Derin tara" ve "Bu siteyi bildir" özelliklerinin arkasındaki küçük sunucu. AI anahtarı yalnızca burada, Worker secret'ı olarak durur.

## Uçlar

| Uç | Ne yapar |
|---|---|
| `POST /v1/scan` | Uzantının gönderdiği sayfa özeti + bulgular → Claude Haiku 5.5 ile karar (`dangerous / suspicious / likely_safe / safe`, gerekçe, tavsiye). 1 saat önbellek. |
| `POST /v1/report` | Kullanıcı bildirimi → bekleyen kuyruk (KV). |
| `GET /v1/x/brand?token=…`, `GET /v1/x/user?handle=…` | Xquik ile X hesabı çözümleme (anahtar burada; sonuçlar KV'de 7 gün / 1 gün önbellek, IP başına 80/gün). |
| `GET /v1/resolve?url=…` | X zaman akışındaki kısa linkleri (t.co, tr.ee, bit.ly…) bizim IP'mizden çözer; kullanıcının IP'si tıklamadan önce hedefe hiç gitmez. Sonuç KV'de 1 gün önbellek, IP başına 300/gün. |
| `GET /v1/community.json` | Onaylanmış topluluk blocklist'i (lists reposu günde bir çeker). |
| `GET /admin?token=…` | Moderasyon paneli: bekleyenleri onayla / reddet. |
| `POST /admin/decide` | Panelin kullandığı karar ucu. |

## AI anahtarının korunması

- Anahtar `wrangler secret` olarak Worker'da; uzantı paketinde, repoda ve istemcide yok.
- Sunucu istemcinin puanına güvenmez: aynı puanlama motoru, lists reposundan çekilen marka listeleri, kendi RDAP yaş sorgusu ve MetaMask blocklist kontrolü ile puanı yeniden hesaplar; model sonucu bu puanın altına inemez. Otomatik listeleme için sunucu puanı ≥35 ve model ≥%90 "tehlikeli" şartı birlikte aranır; public suffix, ücretsiz host, güvenilir ve resmi domainler asla listelenmez.
- Model sabit bir sistem promptu ile çalışır ve yalnızca `verdict` adlı kapalı şemalı bir araçla cevap verebilir; serbest metin dönmez. Birisi `/v1/scan`'e istediği metni gönderse bile alacağı şey sadece "bu sayfa phishing mi" JSON'ıdır.
- Sayfadan gelen her şey `<page>` etiketi içinde "güvenilmeyen veri" olarak verilir; içindeki talimatlar yok sayılır ve scam sinyali sayılır.
- IP başına günde 20 tarama / 10 bildirim, toplamda günde 3000 tarama (ayarlanabilir), 80 KB yük sınırı, `max_tokens` 1024, effort `low`.
- Yayınlandıktan sonra `ALLOWED_ORIGINS` değişkenine uzantının `chrome-extension://<id>` origin'i yazılırsa başka istemciler reddedilir.

Maliyet: tarama başına ~3–4k giriş + ~300 çıkış token; Haiku 5.5 ile yaklaşık 0,0005 $ (10.000 tarama ≈ 5 $). Sistem promptu önbelleğe alınır.

## Kurulum

```bash
cd backend
npm install
npx wrangler login                       # Cloudflare hesabına tarayıcıdan giriş
npx wrangler kv namespace create W3PG_KV # çıkan id'yi wrangler.toml içindeki REPLACE_WITH_KV_ID yerine yaz
npx wrangler secret put ANTHROPIC_API_KEY
npx wrangler secret put XQUIK_API_KEY    # X hesabı sorguları (isteğe bağlı)
npx wrangler secret put ADMIN_TOKEN      # uzun rastgele bir dize; /admin?token=… ile girilir
npx wrangler deploy                      # https://web3-phish-guard-api.<hesap>.workers.dev
```

Sonra:
1. Uzantıdaki sunucu adresi `src/lib/deepscan.ts` içindeki `API_BASE` sabitidir; kendi Worker URL'inle değiştirip build al.
2. Lists reposunda `API_BASE` değişkeni: `gh variable set API_BASE --repo 0xnesQuit/web3-phish-guard-lists --body "https://…workers.dev"`. Günlük Action onaylanan bildirimleri `data/community-blocklist.json` olarak yayınlar; uzantı bunu MetaMask listesiyle aynı güvende (engelleme) kullanır.
3. Moderasyon: `https://…workers.dev/admin` sayfası token'ı bir kez sorar (yalnızca `x-admin-token` başlığıyla gönderilir, URL'de taşınmaz).

Yerel deneme: `npx wrangler dev --local --var ADMIN_TOKEN:test --var ANTHROPIC_API_KEY:sk-…` → `http://127.0.0.1:8787`.
