# Web3 Phish Guard

Chrome / Brave (Manifest V3) uzantısı. Sahte NFT mint ve airdrop "claim / checker" sayfalarını, MetaMask gibi blocklist'lere girmeden önce yerel sezgisellerle yakalayıp uyarır.

Araştırma raporu: [reports/Web3 phishing tespit uzantısı analizi.md](reports/Web3%20phishing%20tespit%20uzant%C4%B1s%C4%B1%20analizi.md)

## Nasıl çalışır

Üç katman, hepsi tarayıcı içinde:

1. **Açık blocklist senkronu** (`src/lib/blocklist.ts`): MetaMask'ın üretim uçları (`stalelist` 12 saatte bir, `diffsSince` 5 dakikada bir), PhishDestroy aktif domain listesi, ScamSniffer açık veritabanı. Eşleşme = doğrudan engelleme.
2. **Alan adı sezgiselleri** (`src/lib/scoring.ts`, ağ çağrısı yok): marka adı + tuzak kelime (`claim`, `rewards`, `checker`, `mint`...), ücretsiz barındırma (`vercel.app`, `pages.dev`...), yapıştırılmış rakamlar, typosquat (uzantı tek başına puan vermez; .top/.bond gibi yoğun kötüye kullanılanlar yalnızca tuzak kelime veya marka ile birlikte sayılır). Sadece şüpheli ama kararsız kalan domainler için RDAP ile kayıt tarihi sorgulanır (yalnızca alan adı gönderilir).
3. **Cüzdan niyeti** (`src/content/provider-guard.ts`): `window.ethereum` ve EIP-6963 sağlayıcıları sarmalanır. Tıklama olmadan bağlantı isteği, Permit / Permit2 / Seaport tipli imzalar, `approve` / `setApprovalForAll` çağrıları puanı yükseltir. Hiçbir istek engellenmez, sadece gözlemlenir.

4. **Sosyal kaynak bağlamı** (`src/lib/origin.ts`, `src/content/x-watch.ts`, `src/content/referrer.ts`): `t.co` yönlendirmesi veya referrer üzerinden linkin X / Discord / Telegram / Reddit'ten geldiği anlaşılır (+10, RDAP sorgusu zorunlu olur). x.com'da tıklanan linkin tweet bağlamı okunur: paylaşan hesap projenin bilinen X hesabı değilse +30, link bir yanıt olarak paylaşılmışsa +10, hesap adında "claim/airdrop/official" geçiyorsa +15. Akıştaki dış linkler tıklanmadan puanlanır ve şüpheli olanların yanına ⚠️ / ⛔ rozeti konur. Bağlam yalnızca puanı yükseltir; resmi hesap paylaştı diye hiçbir domain güvenilir sayılmaz (hesaplar hackleniyor).

5. **X hesabı çözümleme (isteğe bağlı, Xquik)** (`src/lib/xquik.ts`): Ayarlar sayfasına bir Xquik API anahtarı girilirse, şüpheli bir hostname'deki proje adı için X'te hesap aranır (`/x/users/search`, ~20 kredi, 7 gün önbellek), takipçi/Business tik/hesap yaşı ile en olası resmi hesap seçilir ve bio linkindeki domain alınır (Linktree gibi sayfalar takip edilir). Resmi hesap tam bu domaine link veriyorsa puan sıfırlanır; başka bir domaine veriyorsa +25. Linki paylaşan hesap da sorgulanır: resmi hesap değilse +30, 30 günden genç veya 100 takipçiden azsa +15. Yalnızca proje adı ve hesap adı gönderilir, ziyaret edilen URL asla gönderilmez. Anahtar repoya değil `chrome.storage.local`'a yazılır; herkese dağıtımda araya bir backend konmalıdır.

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

Elle bakılan dosyalar (`brands.seed.json`, `action-words.json`, `free-hosts.json`, `tlds.json`, `trusted.json`) değişince `npm run sync:lists` ile public repoya itilmelidir; aksi halde uzantı gömülü kopyayı değil eski uzak kopyayı kullanır. Üretim o repoda çalışır: günlük GitHub Action DefiLlama, CoinMarketCap (`CMC_API_KEY` secret) ve OpenSea (`OPENSEA_API_KEY` secret) scriptlerini çalıştırıp `data/` altına commit eder. Public repoda Actions ücretsizdir; kod bu repoda private kalır. Scriptlerin kaynağı bu repodaki `scripts/` klasörüdür, değişince oraya da kopyalanmalıdır. Elle tetikleme: lists reposunda Actions → "Refresh lists" → Run workflow.

## Diller

Tüm metinler `chrome.i18n` ile tarayıcı diline göre gelir. Tek kaynak `scripts/locales.mjs`; build sırasında `public/_locales/<dil>/messages.json` üretilir. Şu an: en (varsayılan), tr, de, es, fr, pt_BR, ru, hi, zh_CN, ja, ko, vi, id. Yeni dil eklemek için `locales.mjs` içindeki her anahtara o dilin satırını ekleyip `LANGS` listesine kodu yazmak yeterli; eksik çeviriler İngilizceye düşer. Puanlama motoru metin üretmez, yalnızca mesaj anahtarı ve parametre döndürür.

## Gizlilik

Uzantı her ana çerçeve gezintisinin URL'sini yerel olarak değerlendirir; bu, her anti-phishing aracı için zorunludur. Dışarı giden tek trafik: liste güncellemeleri (ziyaretten bağımsız) ve yalnızca şüpheli domainler için `rdap.org`'a alan adı sorgusu. Ziyaret edilen URL'ler hiçbir sunucuya gönderilmez, kaydedilmez.

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

- [ ] Marka → X hesabı çözümleme ve bio linki doğrulama (Xquik, isteğe bağlı backend; sadece şüpheli marka görüldüğünde, URL değil marka adı gönderilir)
- [x] OpenSea verified koleksiyonlardan NFT markaları (`scripts/build-nft-brands.mjs`, anahtar gerekir)
- [ ] GoPlus `phishing_site` ve NFT kontrat riski sorgusu
- [ ] Kullanıcı "yanlış pozitif bildir" akışı
- [ ] Değerlendirme korpusu: eth-phishing-detect git geçmişi + PhishDestroy (pozitif), DefiLlama + MetaMask allowlist (negatif); ölçülmüş FPR
- [ ] Chrome Web Store yayını (Limited Use açıklaması, `<all_urls>` gerekçesi)
