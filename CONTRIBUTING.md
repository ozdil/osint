# Katki Rehberi

## Ilkeler
- Yalnizca pasif ve kamuya acik kaynaklar kullanilir. Genel internete aktif port taramasi, kimlik bilgisi denemesi ve oturum atlatma kesinlikle eklenmez.
- Tum ag okumalari boyut sinirlidir (`http::MAX_BODY`, varsayilan 1 MiB).
- Kullanici kaynakli URL'ler `Http::fetch_untrusted` ile cagrilir (SSRF korumasi, yonlendirme kapali).
- Girdiler `validate` modulunden gecmeden hicbir sorguda kullanilmaz.
- Yapilandirma ve veriler `config::write_atomic` ile yazilir (0600 / 0700, symlink reddi).
- Arayuz ve cikti metinleri Turkcedir; kaynak, belge ve commit mesajlarinda emoji kullanilmaz.

## Kabul kapisi
```
cargo clippy --all-targets -- -D warnings
cargo test
```

## Yeni platform imzasi
`data/sites.json` dosyasina ekleyin veya `~/.config/osint/sites.json` ile yerel olarak genisletin:
`{"ad": "Platform", "url": "https://ornek.com/{}", "kontrol": "durum"}`
`kontrol` degeri `durum` (HTTP 200) veya `metin_yok` (`yok` alanindaki metin yoksa bulundu) olabilir.
