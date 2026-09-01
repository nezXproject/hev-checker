# hev Checker

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python" alt="Python Version">
  <img src="https://img.shields.io/badge/Discord.py-2.3%2B-5865F2?style=for-the-badge&logo=discord" alt="Discord.py">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
</p>

**hev Checker** adalah bot Discord berbasis Python yang dirancang untuk analisis otomatis reputasi IP dan domain secara *real-time*. Bot ini mengintegrasikan API dari **VirusTotal** dan **AbuseIPDB** untuk mendeteksi ancaman siber dan memberikan peringatan otomatis ke saluran khusus tim keamanan.

---

## 🚀 Fitur Utama

- **Pindaian Ganda (IP & Domain):** Mendeteksi alamat IPv4 dan domain secara cerdas.
- **Integrasi VirusTotal v3 API:** Memeriksa status kejahatan (*malicious*) dan kecurigaan (*suspicious*) pada target.
- **Integrasi AbuseIPDB API:** Menganalisis skor kepercayaan penyalahgunaan (*abuse confidence score*) dan total laporan pada IP.
- **Auto-Alert Peringatan Keamanan:** Mengirim notifikasi berlabel *high-priority* (Embed Merah) ke saluran tim jika ditemukan indikasi berbahaya.
- **Konfigurasi Aman:** Seluruh kredensial dikelola melalui variabel lingkungan (`.env`) untuk mencegah kebocoran data.

---

## 🛠️ Prasyarat

Sebelum menjalankan bot, pastikan kamu memiliki:
- Python 3.10 atau versi yang lebih baru.
- Token Bot Discord (dari [Discord Developer Portal](https://discord.com/developers/applications)).
- API Key VirusTotal.
- API Key AbuseIPDB.

---

## 📦 Instalasi

1. **Klon Repositori**
   ```bash
   git clone [https://github.com/nezXproject/hev-checker.git](https://github.com/nezXproject/hev-checker.git)
   cd hev-checker
