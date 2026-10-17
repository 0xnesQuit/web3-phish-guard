# Web3 Phish Guard

Chrome / Brave (Manifest V3) uzantısı. Sahte NFT mint ve airdrop "claim / checker" sayfalarını, MetaMask gibi blocklist'lere girmeden önce yerel sezgisellerle yakalayıp uyarır.

Araştırma raporu: [reports/Web3 phishing tespit uzantısı analizi.md](reports/Web3%20phishing%20tespit%20uzant%C4%B1s%C4%B1%20analizi.md)

## Nasıl çalışır

Üç katman, hepsi tarayıcı içinde:

1. **Açık blocklist senkronu** (`src/lib/blocklist.ts`): MetaMask'ın üretim uçları (`stalelist` 12 saatte bir, `diffsSince` 5 dakikada bir), PhishDestroy aktif domain listesi, ScamSniffer açık veritabanı. Eşleşme = doğrudan engelleme.
2. **Alan adı sezgiselleri** (`src/lib/scoring.ts`, ağ çağrısı yok): marka adı + tuzak kelime (`claim`, `rewards`, `checker`, `mint`...), ücretsiz barındırma (`vercel.app`, `pages.dev`...), kötüye kullanılan TLD'ler, yapıştırılmış rakamlar, typosquat. Sadece şüpheli ama kararsız kalan domainler için RDAP ile kayıt tarihi sorgulanır (yalnızca alan adı gönderilir).
3. **Cüzdan niyeti** (`src/content/provider-guard.ts`): `window.ethereum` ve EIP-6963 sağlayıcıları sarmalanır. Tıklama olmadan bağlantı isteği, Permit / Permit2 / Seaport tipli imzalar, `approve` / `setApprovalForAll` çağrıları puanı yükseltir. Hiçbir istek engellenmez, sadece gözlemlenir.

Puan bantları: `>= 70` tam sayfa uyarı (engelleme, "yine de devam et" ile oturumluk bypass), `35..69` sayfa üstünde sarı şerit, altı sessiz.

Yanlış pozitif frenleri:
- Markanın resmi alan adı ve alt alan adları (`claims.eigenfoundation.org`, `app.uniswap.org`) her zaman 0 puan.
- Resmi domaini doğrulanmamış markalar (ör. seed listesindeki Axis Robotics) ancak tuzak kelime veya ücretsiz host ile birlikte puan alır.
- DefiLlama'dan otomatik gelen ~4.900 marka "düşük güven" katmanındadır: isim ortak kelime olabildiği ve domainler değişebildiği için (`kamino.finance` vs `kamino.com`) tek başına uyarı üretmez.
- 2 yıldan eski domainler puan kaybeder. Kullanıcının "güveniyorum" dediği domainler her şeyi geçersiz kılar.

## Gizlilik

Uzantı her ana çerçeve gezintisinin URL'sini yerel olarak değerlendirir; bu, her anti-phishing aracı için zorunludur. Dışarı giden tek trafik: liste güncellemeleri (ziyaretten bağımsız) ve yalnızca şüpheli domainler için `rdap.org`'a alan adı sorgusu. Ziyaret edilen URL'ler hiçbir sunucuya gönderilmez, kaydedilmez.

## Kurulum (geliştirici)

```bash
npm install
npm run brands   # DefiLlama'dan data/brands.generated.json üretir (isteğe bağlı ama önerilir)
npm run build    # dist/ klasörünü üretir
```

Tarayıcıda: `chrome://extensions` (Brave: `brave://extensions`) → sağ üstten **Developer mode** → **Load unpacked** → `dist/` klasörünü seçin.

Kurulumdan ~6 saniye sonra listeler indirilir; popup'ta sayıları görürsünüz. Listeler inmeden de sezgisel katman çalışır.

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
- [ ] OpenSea verified koleksiyonlardan NFT markaları
- [ ] GoPlus `phishing_site` ve NFT kontrat riski sorgusu
- [ ] Kullanıcı "yanlış pozitif bildir" akışı
- [ ] Değerlendirme korpusu: eth-phishing-detect git geçmişi + PhishDestroy (pozitif), DefiLlama + MetaMask allowlist (negatif); ölçülmüş FPR
- [ ] Chrome Web Store yayını (Limited Use açıklaması, `<all_urls>` gerekçesi)
