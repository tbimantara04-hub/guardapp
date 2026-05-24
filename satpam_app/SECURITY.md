# Dokumen Keamanan Sistem (SSDLC Framework)
Proyek: Gate Control Satpam Poltek SSN

## 1. Fase Requirements (CIA Triad)
Sistem dirancang dengan memprioritaskan tiga pilar keamanan informasi:
- **Confidentiality (Kerahasiaan)**: Identitas mahasiswa (NPM & Nama) dienkripsi menggunakan Hybrid Encryption sebelum dikirim ke server.
- **Integrity (Integritas)**: Menggunakan HMAC-SHA256 dalam protokol Fernet untuk memastikan data log tidak dimanipulasi selama transit.
- **Availability (Ketersediaan)**: Arsitektur database lokal (SQLite) dan caching data mahasiswa di memori memastikan sistem tetap responsif meski dalam jam sibuk.

## 2. Fase Design (Threat Modeling STRIDE)
Kami mengidentifikasi batas kepercayaan (*Trust Boundary*) antara perangkat input satpam dan database server.
- **Spoofing**: Mitigasi dengan mencatat Guard ID pada setiap transaksi.
- **Tampering**: Mitigasi dengan enkripsi end-to-end (Client-side encryption).
- **Repudiation**: Mitigasi dengan fitur **Audit Log** yang mencatat setiap aksi input beserta timestamp yang tidak dapat diubah oleh user biasa.
- **Information Disclosure**: Data sensitif di database tersimpan dalam format terenkripsi (opsional) atau dilindungi akses fisik database lokal.

## 3. HCI-Security (Antarmuka Responsif & Aman)
- **Visual Assurance**: Penambahan badge "Protected by RSA-2048 & Fernet" memberikan kepastian psikologis kepada pengguna bahwa data sedang diproses secara aman.
- **Responsive Layout**: Antarmuka menyesuaikan perangkat (Mobile/Desktop) untuk mencegah kesalahan input (*human error*) yang sering terjadi di layar kecil.

## 4. Fase Implementation (Hybrid Cryptography)
Sistem menggunakan **Hybrid Encryption Pola Ke-2**:
1. **Symmetric (Fernet/AES-128)**: Digunakan untuk mengenkripsi data mahasiswa yang besar karena kecepatannya.
2. **Asymmetric (RSA-2048)**: Digunakan untuk membungkus (*wrap*) kunci simetris saat pengiriman dari browser ke server.
3. **End-to-End**: Kunci privat tetap berada di server, memastikan hanya server yang bisa mendekripsi data.

## 5. Fase Operasional & Audit
- **Least Privilege**: Satpam hanya diberikan akses ke antarmuka input data dan dashboard monitoring terbatas, tanpa akses langsung ke struktur database atau kunci kriptografi.
- **Audit Log**: Mencatat `ID Satpam`, `Aksi`, dan `Waktu` untuk memastikan akuntabilitas (Non-Repudiation).
