# OSINT Platformu

Rust ile yazilmis, pasif ve kaynak odakli acik kaynak istihbarat platformu. CLI ve yerel web paneli tek ikilide.

## Kurulum
```
cargo build --release
./target/release/osint --help
```

## Moduller
| Komut | Icerik |
|---|---|
| `osint domain ornek.com` | DNS (sistem cozumleyici + DoH yedek), RDAP, crt.sh alt alan adlari, SPF/DMARC/DKIM |
| `osint ip 1.2.3.4` | Konum, ASN, ters DNS, Shodan InternetDB (pasif) |
| `osint web ornek.com` | Basliklar, teknoloji, eksik guvenlik basliklari, takip kimlikleri, favicon mmh3, robots, security.txt, Wayback |
| `osint user kullanici` | Platform taramasi, varyasyon onerileri |
| `osint email a@ornek.com` | MX, Gravatar, ucretsiz/gecici saglayici, HIBP (anahtar) |
| `osint phone "+90 5xx..."` | E.164, ulke, hat tipi, arastirma baglantilari |
| `osint media dosya.jpg` | EXIF/GPS, PDF ve DOCX/XLSX/PPTX metaverisi, ozetler, VirusTotal (anahtar) |
| `osint history ornek.com` | Sertifika gecmisi, Wayback uc nokta/parametre envanteri, arsivden e-postalar, GitHub kod aramasi (token) |
| `osint harita a.jpg b.jpg` | Gorsellerdeki GPS konumlarini GeoJSON olarak verir |
| `osint imza-guncelle` | WhatsMyName veritabanini ekler (700'u askin platform) |

## Pivot ve iliskilendirme
```
osint pivot domain ornek.com -d 2 --max-dugum 150 [--genis]
```
Tohum varliktan baslayarak bulgulardan yeni varliklar turetir (alan adi -> IP -> ayni IP'deki alan adlari, web -> e-posta -> kullanici adi -> hesaplar ...). Kok alan adi disindaki varliklar varsayilan olarak genisletilmez. Sonucta ortak gosterge kumeleri (takip kimligi, favicon, IP, ad sunucusu), agirlikli varlik baglanti skorlari ve harici pivot baglantilari (Shodan, Censys, BuiltWith) uretilir.

## Vaka yonetimi
```
osint vaka yeni "Inceleme 1"
osint --vaka 1 domain ornek.com
osint vaka rapor 1 --bicim html > rapor.html
```
Her bulgu SHA-256 butunluk ozetiyle saklanir ve rapor sirasinda dogrulanir.

## Web paneli
```
osint serve --port 8787   # yalnizca 127.0.0.1
```

## API anahtarlari (opsiyonel)
```
osint config set hibp_key ...
osint config set virustotal_key ...
```
`~/.config/osint/config.toml` (0600) icinde saklanir.
