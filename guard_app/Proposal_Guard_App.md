# Proposal Proyek: Sistem Pencatatan Keluar Mahasiswa Berbasis Kriptografi Hibrida (Guard App)

## 1. Latar Belakang
Manajemen pergerakan mahasiswa yang keluar masuk area kampus merupakan aspek krusial dalam menjaga keamanan lingkungan, khususnya pada institusi dengan standar operasional yang ketat. Sistem pencatatan konvensional atau sistem digital yang tidak dilindungi dengan enkripsi memadai sangat rentan terhadap manipulasi data, kebocoran privasi, dan tidak memiliki integritas yang dapat dipertanggungjawabkan dalam proses audit. Oleh karena itu, diperlukan sebuah aplikasi pencatatan (*gate-log*) yang responsif, mudah digunakan oleh petugas keamanan, dan menjamin kerahasiaan serta integritas data operasional melalui implementasi keamanan kriptografi tingkat lanjut.

## 2. Tujuan dan Manfaat
**Tujuan Proyek:**
- Membangun aplikasi berbasis web (*Guard App*) yang responsif dan mudah diakses melalui perangkat *mobile* maupun *desktop* untuk mencatat perizinan keluar mahasiswa.
- Mengamankan transmisi data pencatatan menggunakan arsitektur Kriptografi Hibrida (penggabungan Fernet untuk enkripsi simetris dan RSA untuk enkripsi asimetris).
- Menyediakan sistem dasbor (*dashboard*) sentral untuk monitoring dan *audit logging* oleh administrator atau kepala keamanan.

**Manfaat Proyek:**
- **Integritas Data Tinggi:** Memastikan riwayat pencatatan tidak dapat disadap atau dimanipulasi oleh pihak ketiga (Man-In-The-Middle).
- **Efisiensi Operasional:** Mempercepat proses registrasi keluar masuk melalui antarmuka pengguna yang dirancang khusus (mendukung input individu dan masal).
- **Akuntabilitas:** Setiap pencatatan dilengkapi dengan identitas petugas keamanan (Guard ID) dan stempel waktu (*timestamp*) untuk keperluan penelusuran.

## 3. Fitur Utama Sistem (Fitur Aplikasi)
1. **Sistem Input Ganda (Dual-Mode Input System):**
   - **Individual Entry:** Pencatatan izin keluar untuk satu mahasiswa secara rinci (nama, tujuan, estimasi waktu kembali).
   - **Bulk Entry:** Memungkinkan pencatatan kelompok/rombongan mahasiswa sekaligus untuk mempercepat antrean di gerbang.
2. **Dashboard & Monitoring Real-Time:** 
   - Antarmuka berdesain *Light Mode* profesional yang ramah bagi mata petugas, dilengkapi tabel monitoring dinamis.
3. **Penyimpanan Aman & Audit Trail:**
   - Basis data internal mencatat seluruh aksi, ID penjaga (*Guard ID*), serta status (keluar/kembali).
4. **Hybrid Encryption (Enkripsi Hibrida):**
   - Seluruh data teks (tujuan, identitas) dienkripsi secara lokal pada browser petugas sebelum dikirimkan ke server.

## 4. Arsitektur dan Alur Kerja Kriptografi (Workflow)
Sistem ini menggunakan algoritma **Enkripsi Simetris (Fernet/AES)** untuk kecepatan enkripsi data dalam jumlah besar, dan **Enkripsi Asimetris (RSA)** untuk melindungi kunci simetris tersebut saat ditransmisikan.

### Diagram Alur Kerja (Workflow):
1. **Key Generation (Server):** Saat server (*backend*) dijalankan, sistem menghasilkan *RSA Public Key* dan *RSA Private Key*. *Public Key* di-*serve* ke *frontend*.
2. **Input & Symmetric Generation (Client):** 
   - Petugas mengisi form data mahasiswa.
   - Aplikasi klien (*browser*) membangkitkan sebuah Kunci Simetris (*Symmetric Key* / Fernet Key) acak khusus untuk sesi tersebut.
3. **Client-Side Encryption:**
   - **Data Payload** dienkripsi menggunakan *Symmetric Key* menghasilkan `Encrypted Data` (*Ciphertext*).
   - **Symmetric Key** itu sendiri dienkripsi menggunakan *RSA Public Key* milik server menghasilkan `Encrypted Key`.
4. **Secure Transmission:** Klien mengirimkan `Encrypted Data` dan `Encrypted Key` ke server API melalui jaringan HTTP/HTTPS.
5. **Server-Side Decryption:**
   - Server menerima paket data.
   - Server menggunakan *RSA Private Key* miliknya untuk mendekripsi `Encrypted Key` dan mendapatkan kembali *Symmetric Key*.
   - Server menggunakan *Symmetric Key* tersebut untuk mendekripsi `Encrypted Data` menjadi teks asli (*Plaintext*).
6. **Database Storage:** Teks asli dan *metadata* audit disimpan dengan aman ke dalam basis data relasional.

## 5. Metodologi Penelitian dan Pengembangan
Pengembangan sistem ini menggunakan metodologi **Software Development Life Cycle (SDLC) - Model Iteratif / Agile**, yang terbagi dalam beberapa fase:

1. **Analisis Kebutuhan (Requirements Gathering):**
   - **Kebutuhan Fungsional:** Mengidentifikasi data apa saja yang wajib dicatat di pos penjagaan.
   - **Kebutuhan Keamanan:** *Threat Modeling* untuk mengenali risiko intersepsi jaringan, mengarahkan pada keputusan penggunaan Kriptografi Hibrida.
2. **Desain Sistem & UI/UX:**
   - Pembuatan desain basis data (*Entity-Relationship Diagram*).
   - Perancangan UI/UX berbasis *mobile-first* (agar satpam mudah mengakses dari tablet/HP).
   - Perancangan protokol pengiriman kunci RSA dari *backend* ke *frontend*.
3. **Implementasi (Development):**
   - Pembuatan skrip kriptografi di *backend* (Python `cryptography`).
   - Penulisan antarmuka pengguna dengan HTML/CSS/JS.
   - Pembuatan API/Endpoint untuk integrasi klien dan server.
4. **Pengujian (Testing):**
   - **Unit Testing:** Menguji kekokohan pembangkitan kunci RSA dan Fernet.
   - **Integration Testing:** Memastikan alur enkripsi klien dan dekripsi server berjalan mulus tanpa kehilangan data.
   - **Security Testing:** Mengecek ketahanan API terhadap modifikasi *payload*.
5. **Deployment:** Pemasangan sistem pada server institusi dengan konfigurasi jaringan terbatas (hanya akses intranet/lokal).

## 6. Teknologi yang Digunakan (Tech Stack)
- **Frontend / Client-Side:** HTML5, CSS3, Vanilla JavaScript, API Web Kriptografi (*Web Crypto API* atau library *JSEncrypt/CryptoJS*).
- **Backend / Server-Side:** Python (Flask / FastAPI / modul *http.server* kustom).
- **Kriptografi:** Library `cryptography` Python (RSA 2048-bit, Fernet/AES-128).
- **Database:** SQLite (mudah dideploy dan cukup untuk penggunaan log harian).
