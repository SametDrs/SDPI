# SDPI — Selective DPI Bypass for Discord

<p align="center">
  <img src="assets/app_icon.ico" width="96" height="96" alt="SDPI Logo">
  <br>
  <b>Windows 11 x64 için Discord masaüstü uygulamasına özel, süreç bazlı DPI baypas çözümü.</b>
  <br>
  <sub>Geliştirici: <a href="https://github.com/SametDrs">SametDrs</a></sub>
</p>

---

## 🎯 Neden SDPI? (Geliştirilme Amacı)

Bu projenin geliştirilmesindeki temel çıkış noktası, klasik yöntemlerin yetersiz kalması ve günlük kullanımı olumsuz etkilemesidir:

* **DNS Yetersizliği:** Windows ağ ayarlarından `1.1.1.1` (Cloudflare) veya Google DNS tanımlansa dahi ISS düzeyindeki derin paket inceleme (DPI) ve SNI blokajları aşılamamaktadır.
* **Antivirüs & Genel Araç Çakışmaları:** GoodbyeDPI gibi sistem genelindeki tüm ağ trafiğini yönlendiren araçlar, **Kaspersky** gibi gelişmiş antivirüs/güvenlik yazılımlarıyla çakışabilmekte ya da oyun ve bankacılık trafiğinde kararsızlıklara yol açabilmektedir.

**SDPI**, tüm internet bağlantısını riske atmak yerine **yalnızca Discord istemcisine ait ağ paketlerini (`PID` bazlı)** izole eder. Böylece hem Kaspersky gibi güvenlik yazılımlarıyla sorunsuz çalışır hem de sisteminizin diğer hiçbir trafiğine dokunmadan Discord'u stabil hale getirir.

---

## 🚀 Öne Çıkan Özellikler

- **Süreç Bazlı İzolasyon (Process-Bound):** Trafik filtreleme IP veya alan adına göre değil, `%LOCALAPPDATA%\Discord*` yol sınırları ve `"Discord Inc."` Authenticode dijital imzasıyla doğrulanmış Discord süreçlerine (`PID`) göre yapılır.
- **Sıfır Yan Etki (`packets_non_discord_modified == 0`):** Tarayıcılar (Chrome, Edge, Firefox), oyunlar (Steam, Riot Client) ve sistem servisleri ağ motorundan kesinlikle etkilenmez.
- **Ses ve Görüntü Dokunulmazlığı:** Sesli sohbet, kamera ve ekran paylaşımına ait UDP (RTP/DTLS) paketleri doğrudan passthrough bırakılır; paket kaybı veya gecikme yaşanmaz.
- **Canlı Gecikme (Ping) Göstergesi:** Discord kenar sunucularına olan anlık ağ gecikmesi arayüzde gerçek zamanlı olarak izlenir.
- **Tek Tıkla "Onar" (Bağlantı Onarımı):** Discord güncelleme veya ses bağlantısı döngüsünde kaldığında DNS önbelleğini temizler ve Discord ağ servisini tek tıkla yeniler.
- **Akıllı Otomatik Mod Geçişi (Auto-Fallback):** Standart modda ISP blokajı aşılamazsa kullanıcı müdahalesine gerek kalmadan alternatif uyumluluk modlarını dener.
- **Sistem Tepsisi Entegrasyonu:** Windows açılışında sessizce sağ altta başlayabilir; pencere kapatıldığında sistem tepsisinde çalışmaya devam eder.
- **Çift Başlatıcı Desteği:** İster derlenmiş yerel [SDPI.exe](SDPI.exe) üzerinden çift tıklamayla, isterseniz Python kaynak kodundan doğrudan çalıştırılabilir.

---

## 🛠️ Hızlı Başlangıç

### Yöntem 1: Doğrudan Çalıştırma (`SDPI.exe`)
1. Projeyi indirin veya klonlayın.
2. Ana dizindeki **`SDPI.exe`** dosyasına çift tıklayarak uygulamayı başlatın.
3. **"Bağlantıyı Başlat"** düğmesine tıklayın ve gelen yönetici iznini (UAC) onaylayın.

### Yöntem 2: Kaynak Koddan Çalıştırma (Python)
Gereksinimleri yükleyin ve başlatın:

```powershell
pip install -r requirements.txt
python -m app.main
```

---

## ⚙️ Gereksinimler

- **İşletim Sistemi:** Windows 10 / 11 (64-bit)
- **Python (Kaynak kod için):** Python 3.10 veya üzeri
- **Bağımlılıklar:** `PySide6>=6.7.0`, `psutil>=5.9.0`
- **Ağ Sürücüsü:** WinDivert 2.2.2 (resmî imzalı ikili dosyalar `engine/` ve `drivers/` dizininde hazırdır)

---

## 🔒 Güvenlik ve Mimari İlkeleri

1. **Kill-Switch Yoktur:** Motor durdurulduğunda bilgisayarınızın genel internet bağlantısı asla kesilmez.
2. **Güvenli Soket Yönetimi:** Motor kapandığında yalnızca Discord'un açık TCP oturumları ve ağ servisi sıfırlanır; diğer uygulamalar kesintisiz çalışmaya devam eder.
3. **Korumalı IPC İletişimi:** C++ paket motoru ile Python arayüzü arasındaki iletişim, kullanıcının benzersiz SID'ine kilitlenmiş yerel Win32 Named Pipe DACL ile korunur.

---

## 💡 Teşekkür & Referanslar (Acknowledgments)

Bu proje, açık kaynak topluluğunun değerli araştırmaları ve araçları sayesinde hayata geçirilmiştir:

* **[GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI)** (by ValdikSS) — Pasif DPI engelleme analizi ve TCP/TLS paket bölümleme teknikleri.
* **[Zapret](https://github.com/bol-van/zapret)** (by bol-van) — Gelişmiş multi-platform DPI atlatma teknikleri ve stratejileri.

---

## 📄 Lisans

Bu proje [Apache License 2.0](LICENSE) kapsamında lisanslanmıştır.  
Kullanılan harici bileşen: [WinDivert](https://reqrypt.org/windivert.html) (LGPL-3.0 / GPL-2.0).
