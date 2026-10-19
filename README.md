# Guard3

Chrome / Brave (Manifest V3) uzantısı. Sahte NFT mint ve airdrop "claim / checker" sayfalarını, MetaMask gibi blocklist'lere girmeden önce yerel sezgisellerle yakalayıp uyarır.

Araştırma raporu: [reports/Web3 phishing tespit uzantısı analizi.md](reports/Web3%20phishing%20tespit%20uzant%C4%B1s%C4%B1%20analizi.md)

## Nasıl çalışır

Üç katman, hepsi tarayıcı içinde:

1. **Açık blocklist senkronu** (`src/lib/blocklist.ts`): MetaMask'ın üretim uçları (`stalelist` 12 saatte bir, `diffsSince` 5 dakikada bir), PhishDestroy aktif domain listesi, ScamSniffer açık veritabanı. Eşleşme = doğrudan engelleme.
2. **Alan adı sezgiselleri** (`src/lib/scoring.ts`, ağ çağrısı yok): marka adı + tuzak kelime (`claim`, `rewards`, `checker`, `mint`...), ücretsiz barındırma (`vercel.app`, `pages.dev`...), yapıştırılmış rakamlar, typosquat (uzantı tek başına puan vermez; .top/.bond gibi yoğun kötüye kullanılanlar yalnızca tuzak kelime veya marka ile birlikte sayılır). Sadece şüpheli ama kararsız kalan domainler için RDAP ile kayıt tarihi sorgulanır (yalnızca alan adı gönderilir).
3. **Cüzdan niyeti** (`src/content/provider-guard.ts`): `window.ethereum` ve EIP-6963 sağlayıcıları sarmalanır. Tıklama olmadan bağlantı isteği, Permit / Permit2 / Seaport tipli imzalar, `approve` / `setApprovalForAll` çağrıları puanı yükseltir. Riskli türler (sınırsız approve, setApprovalForAll, Permit/Permit2, Seaport/Blur emirleri, EIP-3009, EIP-7702, eth_sign, EOA'ya izin, zehirlenmiş adres) cüzdana gitmeden önce onay penceresinde tutulur; reddedilirse sayfa 4001 hatası görür. Kapı, hazır drainer kitlerini durdurur; bu uzantıyı özel olarak hedefleyen (örneğin sayfaya gömülü cüzdan kullanan) kod kapsam dışıdır.

3b. **Bekletmeli onay (gate)** (`src/content/provider-guard.ts`, `src/content/bridge.ts`, `src/lib/txdecode.ts`): `approve`/`increaseAllowance` (sınırsız miktar tespiti), `setApprovalForAll`, Permit/Permit2 (tekil, batch, witness, PermitForAll), Seaport/Blur siparişleri, `transfer`/`transferFrom`, `multicall` içine gömülü çağrılar, EIP-5792 `wallet_sendCalls`, EIP-7702 `authorizationList`, `eth_sign` çözümlenir. Spender/operator için aynı provider üzerinden `eth_getCode` sorulur; düz cüzdan adresine (EOA) verilen izin, address poisoning (ilk 4 + son 4 hex aynı), 7702 ve eth_sign **her sitede**, diğer riskli istekler ise şüpheli/bilinmeyen sitelerde modal ile bekletilir; "Reddet" EIP-1193 4001 hatası döndürür. Köprü 8 sn içinde cevap vermezse istek serbest bırakılır (dApp asla kilitlenmez); onay penceresi açıldıktan sonra ise kullanıcı cevap verene kadar bekletilir.
3b+. **İşlem simülasyonu** (`src/lib/simulate.ts`, `src/background.ts` `w3pg:simulate`, `src/content/bridge.ts`): bekletilen `eth_sendTransaction` / `eth_signTransaction` (ve `wallet_sendCalls` içindeki riskli çağrı) için onay penceresi açılırken herkese açık bir RPC'ye (publicnode / 1rpc / dRPC / MEV Blocker; zincirler: 1, 10, 56, 137, 8453, 42161) `eth_simulateV1` + `traceTransfers` isteği gider ve günlükler çözülür: "Cüzdanınızdan çıkar", "Size geri gelir", "Size hiçbir şey geri gelmez", "Yeni onay", işlem geri alınırsa (revert) uyarı. Varsayılan açık, ayarlar sayfasından kapatılır; tarayıcıdan doğrudan gider (sunucumuza değil), yalnızca bekletilen işlemin from/to/data/value ve zincir kimliği gönderilir (ayrıntı: `PRIVACY.md`). Tab başına 2 sn'de 1, dakikada 20 sınırı; her uç 5 sn zaman aşımı; simülasyon yoksa pencere onsuz çalışır. Avalanche gibi desteklenmeyen zincirlerde "simülasyon yok" satırı görünür.
3c. **Seed phrase / özel anahtar koruması** (`src/content/seed-guard.ts`): input/paste/submit anında BIP39 (12–24 kelime, %90 eşleşme), 64-hex ve Solana base58 anahtarları yakalanır; tam ekran durdurma. Metin hiçbir yere gönderilmez.
3d. **ClickFix / pano**: `navigator.clipboard.writeText`, `execCommand("copy")` ve `copy` olayı izlenir; panoya komut (powershell, mshta, `curl | sh`...) kopyalanması veya seçili adresin başka bir adresle değiştirilmesi +60.
3e. **Sahte cüzdan**: EIP-6963 `rdns`/`name` uyuşmazlığı +40; Chrome Web Store'da cüzdan adı taşıyan ama resmi ID olmayan uzantı sayfası engellenir.

4. **Sosyal kaynak bağlamı** (`src/lib/origin.ts`, `src/content/x-watch.ts`, `src/content/referrer.ts`): `t.co` yönlendirmesi veya referrer üzerinden linkin X / Discord / Telegram / Reddit'ten geldiği anlaşılır (+10, RDAP sorgusu zorunlu olur). x.com'da tıklanan linkin tweet bağlamı okunur: paylaşan hesap projenin bilinen X hesabı değilse +30, link bir yanıt olarak paylaşılmışsa +10, hesap adında "claim/airdrop/official" geçiyorsa +15. Akıştaki dış linkler tıklanmadan puanlanır ve şüpheli olanların yanına ⚠️ / ⛔ rozeti konur. Bağlam yalnızca puanı yükseltir; resmi hesap paylaştı diye hiçbir domain güvenilir sayılmaz (hesaplar hackleniyor).

5. **X hesabı çözümleme (Xquik, sunucu üzerinden)** (`src/lib/xquik.ts` → Worker `/v1/x/brand`, `/v1/x/user`; mantık `src/lib/xquik-core.ts`): şüpheli bir hostname'deki proje adı için X'te hesap aranır (`/x/users/search`, ~20 kredi, 7 gün önbellek), takipçi/Business tik/hesap yaşı ile en olası resmi hesap seçilir ve bio linkindeki domain alınır (Linktree gibi sayfalar takip edilir). Resmi hesap tam bu domaine link veriyorsa puan sıfırlanır; başka bir domaine veriyorsa +25. Linki paylaşan hesap da sorgulanır: resmi hesap değilse +30, 30 günden genç veya 100 takipçiden azsa +15. Yalnızca proje adı ve hesap adı gönderilir, ziyaret edilen URL asla gönderilmez. Xquik anahtarı yalnızca Worker'da (`XQUIK_API_KEY` secret) durur; uzantıda hiçbir anahtar veya ayarlanabilir sunucu adresi yoktur.

Puan bantları: `>= 70` tam sayfa uyarı (engelleme, "yine de devam et" ile oturumluk bypass), `35..69` sayfa üstünde sarı şerit, altı sessiz.

Yanlış pozitif frenleri:
- Markanın resmi alan adı ve alt alan adları (`claims.eigenfoundation.org`, `app.uniswap.org`) her zaman 0 puan.
- Resmi domaini doğrulanmamış markalar (ör. seed listesindeki Axis Robotics) ancak tuzak kelime veya ücretsiz host ile birlikte puan alır.
- DefiLlama'dan otomatik gelen ~4.900 marka "düşük güven" katmanındadır: isim ortak kelime olabildiği ve domainler değişebildiği için (`kamino.finance` vs `kamino.com`) tek başına uyarı üretmez.
- 2 yıldan eski domainler puan kaybeder. Kullanıcının "güveniyorum" dediği domainler her şeyi geçersiz kılar.

## Derin tarama ve bildirim (backend/)

Popup'taki **Derin tara** butonu, sadece kullanıcı isteyince çalışan pahalı katmandır: `page-scan.js` sayfanın yapısal özetini çıkarır (kütüphaneler, script adları, obfuscation izleri, link dağılımı, cüzdan butonları, seed phrase alanları, geri sayım, drainer imzaları), background dış scriptleri indirip drainer string'lerini tarar, GoPlus `phishing_site`'a sorar, RDAP ve X çözümlemesini tamamlar ve hepsini `backend/` altındaki Cloudflare Worker'a gönderir; Worker Claude Haiku 5.5'ten kapalı şemalı bir karar alır. AI anahtarı yalnızca Worker'da durur. **Bu siteyi bildir** butonu bildirimi aynı Worker'a yollar; onaylananlar lists reposundaki `community-blocklist.json`'a girer ve uzantıda engelleme listesi olarak kullanılır. Kurulum ve güvenlik modeli: [backend/README.md](backend/README.md).

## Listelerin güncel tutulması

Marka ve sinyal listeleri uzantının içinde gömülü gelir (ilk kurulumda sıfır gecikme) ve 12 saatte bir public `web3-phish-guard-lists` reposundan (`https://raw.githubusercontent.com/0xnesQuit/web3-phish-guard-lists/main/data/`) tazelenir (`src/lib/lists.ts`, `refreshRemoteData`). Önce `manifest.json` çekilir; yalnızca yeni bir yayın varsa dosyalar indirilip `chrome.storage.local`'a yazılır ve gömülü kopyanın önüne geçer. İndirilen şey yalnızca JSON veridir.

Uzak listeler imzalıdır: lists reposunun Action'ı `manifest.json`'ı ECDSA P-256 ile imzalar (`LISTS_SIGNING_KEY` secret), uzantı gömülü public anahtarla imzayı ve her dosyanın SHA-256'sını doğrular; imzasız/bozuk manifest reddedilir ve gömülü kopya kullanılır. Uzak `trusted.json` gömülü listeden en fazla 50 domain fazla olabilir. Elle bakılan dosyalar (`brands.seed.json`, `action-words.json`, `free-hosts.json`, `tlds.json`, `trusted.json`) değişince `npm run sync:lists` ile public repoya itilmelidir; aksi halde uzantı gömülü kopyayı değil eski uzak kopyayı kullanır. Üretim o repoda çalışır: günlük GitHub Action DefiLlama, CoinMarketCap (`CMC_API_KEY` secret) ve OpenSea (`OPENSEA_API_KEY` secret) scriptlerini çalıştırıp `data/` altına commit eder. Public repoda Actions ücretsizdir. Scriptlerin kaynağı bu repodaki `scripts/` klasörüdür, değişince oraya da kopyalanmalıdır. Elle tetikleme: lists reposunda Actions → "Refresh lists" → Run workflow.

## Diller

Tüm metinler `chrome.i18n` ile tarayıcı diline göre gelir. Tek kaynak `scripts/locales.mjs`; build sırasında `public/_locales/<dil>/messages.json` üretilir. Şu an: en (varsayılan), tr, de, es, fr, pt_BR, ru, hi, zh_CN, ja, ko, vi, id. Yeni dil eklemek için `locales.mjs` içindeki her anahtara o dilin satırını ekleyip `LANGS` listesine kodu yazmak yeterli; eksik çeviriler İngilizceye düşer. Puanlama motoru metin üretmez, yalnızca mesaj anahtarı ve parametre döndürür.

## Gizlilik

Uzantı her ana çerçeve gezintisinin URL'sini önce yerel olarak değerlendirir. Dışarı giden trafik: liste güncellemeleri (ziyaretten bağımsız), yalnızca şüpheli domainler için registry'nin RDAP servisine alan adı sorgusu, şüpheli sayfalar için X hesabı sorgusu (sadece proje adı / handle), X zaman akışındaki kısa linklerin sunucumuz üzerinden çözümlenmesi, bekletilen bir işlemin simülasyonu için herkese açık RPC'ye (publicnode / 1rpc / dRPC) from/to/data/value ve zincir kimliği (ayarlardan kapatılabilir), ve kullanıcı isterse deep scan / bildirim (URL sorgu dizesi olmadan). Ayrıntılar `PRIVACY.md`'de.

## Kurulum (geliştirici)

```bash
npm install
npm run brands   # DefiLlama'dan data/brands.generated.json üretir (isteğe bağlı ama önerilir)
CMC_API_KEY=... npm run brands:cmc         # CoinMarketCap'teki token projelerinden data/brands.cmc.json (ücretsiz Basic anahtar, ~60 kredi)
OPENSEA_API_KEY=... npm run brands:nft   # OpenSea verified/approved koleksiyonlardan data/brands.nft.json (isteğe bağlı; anahtar yalnızca burada kullanılır)
npm run build    # dist/ klasörünü üretir
```

Tarayıcıda: `chrome://extensions` (Brave: `brave://extensions`) → sağ üstten **Developer mode** → **Load unpacked** → `dist/` klasörünü seçin.

Kurulumdan ~6 saniye sonra listeler indirilir; popup'ta sayıları görürsünüz. Listeler inmeden de sezgisel katman çalışır.

## Firefox

```bash
npm run build:firefox      # dist-firefox/ (public/manifest.firefox.json: event-page background, gecko id, veri toplama beyanı)
npm run lint:firefox       # Mozilla web-ext lint (0 hata beklenir)
```

Firefox'ta deneme: `about:debugging#/runtime/this-firefox` → **Load Temporary Add-on** → `dist-firefox/manifest.json`. Minimum Firefox 140 (veri toplama izinleri için). Derin tarama ilk kez çalışırken Firefox, beyan edilen isteğe bağlı veri toplama iznini sorar.

## Paketleme

`npm run build:all && npm run package` → `packages/` altında Chrome/Edge/Brave için ve Firefox için ayrı zip'ler.

## Test

```bash
npm test                     # vitest: puanlama ve ayrıştırma birim testleri
node scripts/check.mjs https://rewards-axisrobotics.xyz https://uniswap.org   # komut satırından puan
```

## Proje yapısı

```
public/            manifest, warning.html, popup.html, ikonlar
data/              action-words, free-hosts, tlds, brands.seed (elle), brands.generated (DefiLlama)
src/background.ts  gezinti yakalama, puanlama, uyarı yönlendirme, liste alarmları
src/lib/           hostname ayrıştırma, puanlama, blocklist, rdap, durum
src/content/       provider-guard (MAIN world), bridge, overlay
src/pages/         warning ve popup scriptleri
scripts/           build, build-brands, make-icons, check
test/              vitest
```

## Yol haritası

- [x] Marka → X hesabı çözümleme ve bio linki doğrulama (Xquik, Worker üzerinden; sadece marka adı / handle gönderilir)
- [x] OpenSea verified koleksiyonlardan NFT markaları (`scripts/build-nft-brands.mjs`, anahtar gerekir)
- [x] GoPlus `phishing_site` sorgusu (deep scan içinde)
- [x] Kullanıcı bildirimi + moderasyon paneli; "güven" ile yanlış pozitif geri alma
- [x] Popülerlik koruması (Tranco top-50k): tek bir liste kaydı yaygın bir siteyi engelleyemez
- [x] İşlem simülasyonu: bekletilen işlemlerde "ne çıkar / ne geri gelir / yeni onay" (herkese açık RPC; EVM `eth_simulateV1` ve `wallet_sendCalls` toplu çağrıları, Solana `simulateTransaction` (publicnode); EIP-7702 ve toplu çağrı özetleri onay penceresinde; imza isteklerinin simülasyonu ve Avalanche yok)
- [ ] Tuzak cüzdan (decoy wallet) modu: şüpheli sitelere gerçek cüzdan yerine boş bir tuzak cüzdan sunmak (planlı)
- [ ] Değerlendirme korpusu: eth-phishing-detect git geçmişi + PhishDestroy (pozitif), Tranco + MetaMask allowlist (negatif); ölçülmüş FPR (şimdilik inceleme turlarında elle ölçülüyor)
- [ ] Chrome Web Store / AMO yayını (Limited Use açıklaması, `<all_urls>` gerekçesi)
