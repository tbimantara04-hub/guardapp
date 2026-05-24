"""
Guard App — Backend API Server
===============================
Arsitektur Keamanan: Lightweight Hybrid Cryptography
  • Asymmetric (Key Exchange) : ECC secp256r1 / NIST P-256 (ECDH)
  • Symmetric  (Payload Data) : Ascon-AEAD128 (NIST Lightweight Standard)
  • Key Wrapping              : AES-128-GCM via HKDF-SHA256

Workflow Dekripsi Server:
  1. Terima ephemeral_public_key + encrypted_ascon_key + ciphertext
  2. ECDH(server_private, ephemeral_public) → shared_secret
  3. HKDF-SHA256(shared_secret) → KEK (Key Encrypting Key)
  4. AES-128-GCM-Decrypt(KEK, encrypted_ascon_key) → ascon_session_key
  5. Ascon-AEAD128-Decrypt(ascon_session_key, ciphertext) → JSON plaintext
  6. Parse JSON array → simpan setiap entri ke SQLite

Author: Satria Tegar Bimantara
"""

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

# [CRYPTO] Modul kriptografi untuk operasi ECC dan key derivation
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from werkzeug.security import generate_password_hash, check_password_hash

# [CRYPTO] Modul Ascon untuk enkripsi/dekripsi simetris ringan
import ascon

import os
import json
import base64
import sqlite3

# ============================================================
# Flask App Configuration
# ============================================================

app = Flask(__name__, static_folder='../static')
CORS(app)
basedir = os.path.abspath(os.path.dirname(__file__))

# Database path — gunakan /tmp untuk Vercel (read-only filesystem)
if os.environ.get('VERCEL'):
    DB_PATH = '/tmp/guard.db'
else:
    db_dir = os.path.join(basedir, '../db')
    os.makedirs(db_dir, exist_ok=True)
    DB_PATH = os.path.join(db_dir, 'guard.db')


# ============================================================
# ECC Key Management (secp256r1 / NIST P-256)
# ============================================================

def load_or_generate_ecc_keys():
    """
    Memuat ECC Private Key. Urutan prioritas:
      1. Environment variable ECC_PRIVATE_KEY_PEM (WAJIB di produksi)
      2. File lokal keys/ecc_private.pem
      3. Generate pasangan kunci baru (hanya untuk development)
    """
    # Prioritas 1: Environment variable
    pem_env = os.environ.get('ECC_PRIVATE_KEY_PEM')
    if pem_env:
        # [CRYPTO] Memuat Private Key ECC dari PEM di environment variable
        key = serialization.load_pem_private_key(pem_env.encode('utf-8'), password=None)
        print("[Security] ECC Private Key loaded from environment variable.")
        return key

    # Prioritas 2: File lokal
    key_dir = os.path.join(basedir, 'keys')
    key_path = os.path.join(key_dir, 'ecc_private.pem')

    if os.path.exists(key_path):
        with open(key_path, 'rb') as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
        print("[Security] ECC Private Key loaded from file.")
        return key

    # Prioritas 3: Generate baru (development only)
    print("[Security] WARNING — Generating new ECC key pair. Set ECC_PRIVATE_KEY_PEM in production!")

    # [CRYPTO] Generate pasangan kunci ECC pada kurva secp256r1 (NIST P-256)
    # Kurva ini memberikan keamanan ~128-bit dengan ukuran kunci 256-bit,
    # jauh lebih efisien dibanding RSA-2048 (terutama untuk perangkat mobile).
    private_key = ec.generate_private_key(ec.SECP256R1())

    os.makedirs(key_dir, exist_ok=True)

    # Simpan Private Key (PEM PKCS8, tanpa password untuk development)
    with open(key_path, 'wb') as f:
        f.write(private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        ))

    # Simpan Public Key (PEM SubjectPublicKeyInfo)
    with open(os.path.join(key_dir, 'ecc_public.pem'), 'wb') as f:
        f.write(private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print("[Security] New ECC key pair generated and saved to keys/.")
    return private_key


# Inisialisasi kunci ECC saat server dimulai
ecc_private_key = load_or_generate_ecc_keys()
ecc_public_key = ecc_private_key.public_key()


# ============================================================
# Database Initialization
# ============================================================

def get_db():
    """Mendapatkan koneksi database SQLite."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Inisialisasi skema database dan default user."""
    conn = get_db()

    # Muat schema.sql jika tersedia
    schema_path = os.path.join(basedir, 'schema.sql')
    if os.path.exists(schema_path):
        with open(schema_path, 'r') as f:
            conn.executescript(f.read())
    else:
        # Fallback inline schema
        conn.executescript('''
            CREATE TABLE IF NOT EXISTS gate_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                guard_id TEXT NOT NULL,
                nama_mahasiswa TEXT NOT NULL,
                tujuan TEXT NOT NULL,
                estimasi_kembali TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                guard_id TEXT NOT NULL,
                action TEXT NOT NULL,
                entry_count INTEGER DEFAULT 1,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            );
        ''')

    # Buat default admin jika belum ada
    cursor = conn.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            ('admin', generate_password_hash('password123'))
        )
        conn.commit()
        print("[DB] Default admin user created (admin / password123).")

    conn.close()


try:
    init_db()
    print("[DB] Database initialized successfully.")
except Exception as e:
    print(f"[DB] Initialization warning: {e}")


# ============================================================
# Cryptographic Utility Functions
# ============================================================

def ecdh_derive_kek(ephemeral_pub_raw, info_context):
    """
    [CRYPTO] Melakukan ECDH Key Agreement dan menurunkan KEK via HKDF.

    Alur:
      1. Rekonstruksi ephemeral public key dari raw bytes (uncompressed point, 65 bytes)
      2. ECDH: server_private × ephemeral_public → shared_secret (32 bytes untuk P-256)
      3. HKDF-SHA256(shared_secret, info) → KEK (16 bytes untuk AES-128-GCM)

    Args:
        ephemeral_pub_raw: bytes — Raw uncompressed point (65 bytes: 0x04 || x || y)
        info_context: bytes — Domain separation string untuk HKDF

    Returns:
        bytes — Key Encrypting Key (16 bytes)
    """
    # [CRYPTO] Rekonstruksi ECC Public Key dari format uncompressed point
    ephemeral_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), ephemeral_pub_raw
    )

    # [CRYPTO] Elliptic Curve Diffie-Hellman (ECDH)
    # Kedua pihak menghasilkan shared secret yang IDENTIK:
    #   Client:  ephemeral_private × server_public  = shared_secret
    #   Server:  server_private × ephemeral_public   = shared_secret
    shared_secret = ecc_private_key.exchange(ec.ECDH(), ephemeral_public_key)

    # [CRYPTO] HKDF-SHA256 — Key Derivation Function
    # Mengubah shared_secret (yang mungkin bias) menjadi kunci kriptografis
    # dengan distribusi bit yang seragam.
    # Parameter `info` memberikan domain separation sehingga kunci yang diturunkan
    # hanya valid untuk konteks tertentu (key wrapping vs login, dll).
    kek = HKDF(
        algorithm=hashes.SHA256(),
        length=16,                    # 128-bit output untuk AES-128-GCM
        salt=None,                    # Default: HashLen zero bytes (per RFC 5869)
        info=info_context
    ).derive(shared_secret)

    return kek


def decrypt_ascon_key(ephemeral_pub_raw, encrypted_ascon_key, key_iv):
    """
    [CRYPTO] Mendekripsi Kunci Sesi Ascon yang dibungkus dengan AES-128-GCM.

    Args:
        ephemeral_pub_raw: bytes — Ephemeral ECC public key (65 bytes)
        encrypted_ascon_key: bytes — Kunci Ascon terenkripsi (16 bytes ct + 16 bytes GCM tag = 32 bytes)
        key_iv: bytes — AES-GCM initialization vector (12 bytes)

    Returns:
        bytes — Kunci sesi Ascon (16 bytes)
    """
    kek = ecdh_derive_kek(ephemeral_pub_raw, b"guard-app-ascon-key-wrap")

    # [CRYPTO] AES-128-GCM Decryption — membuka bungkusan kunci sesi Ascon
    # GCM memberikan authenticated encryption: jika kunci dibungkus dengan
    # KEK yang salah atau data dimanipulasi, dekripsi akan gagal.
    aesgcm = AESGCM(kek)
    ascon_key = aesgcm.decrypt(key_iv, encrypted_ascon_key, None)

    return ascon_key


def ascon_decrypt_payload(ascon_key, nonce, associated_data, ciphertext):
    """
    [CRYPTO] Mendekripsi payload JSON menggunakan Ascon-AEAD128.

    Ascon-AEAD128 (= Ascon-128) adalah standar NIST untuk Lightweight
    Authenticated Encryption. Memberikan:
      • Confidentiality — data terenkripsi
      • Integrity       — tag autentikasi 128-bit
      • Binding         — associated_data (guard_id) terikat ke ciphertext

    Args:
        ascon_key: bytes (16) — Kunci sesi Ascon
        nonce: bytes (16) — Nonce unik
        associated_data: bytes — guard_id (diautentikasi, tidak dienkripsi)
        ciphertext: bytes — Data terenkripsi + tag autentikasi

    Returns:
        str — JSON string plaintext

    Raises:
        ValueError — Jika tag autentikasi tidak valid (data dimanipulasi)
    """
    # [CRYPTO] Ascon-AEAD128 Authenticated Decryption
    # Variant "Ascon-128" pada library Python setara dengan NIST Ascon-AEAD128
    # Fungsi ini memverifikasi tag autentikasi 128-bit secara otomatis.
    # Jika tag tidak cocok → mengembalikan None (data mungkin dimanipulasi).
    plaintext = ascon.ascon_decrypt(
        key=ascon_key,
        nonce=nonce,
        associateddata=associated_data,
        ciphertext=ciphertext,
        variant="Ascon-128"
    )

    if plaintext is None:
        raise ValueError(
            "Verifikasi tag autentikasi Ascon gagal. "
            "Data mungkin telah dimanipulasi (tampered)."
        )

    return plaintext.decode('utf-8')


# ============================================================
# API Routes — Static Files
# ============================================================

@app.route('/')
def index():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/login')
def login_page():
    return send_from_directory(app.static_folder, 'login.html')

@app.route('/dashboard')
def dashboard_page():
    return send_from_directory(app.static_folder, 'dashboard.html')

@app.route('/<path:filename>')
def serve_static(filename):
    return send_from_directory(app.static_folder, filename)


# ============================================================
# API Routes — ECC Public Key Distribution
# ============================================================

@app.route('/api/get_ecc_public_key', methods=['GET'])
def get_ecc_public_key():
    """
    Mengirimkan ECC Public Key server ke Frontend.

    Format: Base64-encoded raw uncompressed point (65 bytes untuk P-256).
    Byte pertama = 0x04, diikuti x-coordinate (32 bytes) dan y-coordinate (32 bytes).
    Frontend akan menggunakan kunci ini untuk ECDH key agreement.
    """
    # [CRYPTO] Export ECC Public Key sebagai uncompressed point
    raw_pub = ecc_public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )

    return jsonify({
        "public_key": base64.b64encode(raw_pub).decode('utf-8'),
        "curve": "P-256",
        "format": "uncompressed"
    })


# ============================================================
# API Routes — Authentication (ECC-encrypted Login)
# ============================================================

@app.route('/api/login', methods=['POST'])
def api_login():
    """
    Autentikasi petugas keamanan dengan kredensial terenkripsi ECC.

    Request Body:
    {
        "ephemeral_public_key": "<base64>",     // Ephemeral ECC pub key (65 bytes raw)
        "encrypted_credentials": "<base64>",    // AES-GCM encrypted {username, password}
        "iv": "<base64>"                        // AES-GCM IV (12 bytes)
    }

    Alur:
      1. ECDH(server_private, ephemeral_public) → shared_secret
      2. HKDF(shared_secret, info="guard-app-login") → AES key
      3. AES-GCM-Decrypt(key, credentials) → {username, password}
      4. Verifikasi password hash di database
    """
    data = request.json

    try:
        ephemeral_pub = base64.b64decode(data['ephemeral_public_key'])
        encrypted_creds = base64.b64decode(data['encrypted_credentials'])
        creds_iv = base64.b64decode(data['iv'])

        # [CRYPTO] Derive KEK untuk login (domain separation: "guard-app-login")
        kek = ecdh_derive_kek(ephemeral_pub, b"guard-app-login")

        # [CRYPTO] AES-128-GCM Decrypt kredensial
        aesgcm = AESGCM(kek)
        creds_json = aesgcm.decrypt(creds_iv, encrypted_creds, None)
        creds = json.loads(creds_json.decode('utf-8'))

        username = creds.get('username', '')
        password = creds.get('password', '')

        # Verifikasi di database
        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        conn.close()

        if user and check_password_hash(user['password_hash'], password):
            token = base64.b64encode(username.encode()).decode()
            return jsonify({
                "status": "success",
                "token": token,
                "username": username
            }), 200
        else:
            return jsonify({
                "status": "error",
                "message": "Username atau password salah."
            }), 401

    except Exception:
        return jsonify({
            "status": "error",
            "message": "Username atau password salah."
        }), 400


# ============================================================
# API Routes — Encrypted Data Submission (Inti Kriptografi)
# ============================================================

@app.route('/api/submit_encrypted_entry', methods=['POST'])
def submit_encrypted_entry():
    """
    Menerima dan mendekripsi payload terenkripsi Hybrid (ECDH + Ascon).

    Request Body (JSON):
    {
        "ephemeral_public_key" : "<base64>",  // Ephemeral ECC pub (65 bytes)
        "encrypted_ascon_key"  : "<base64>",  // Kunci Ascon dibungkus AES-GCM (32 bytes)
        "key_iv"               : "<base64>",  // AES-GCM IV untuk key wrapping (12 bytes)
        "ascon_nonce"          : "<base64>",  // Nonce Ascon-AEAD128 (16 bytes)
        "ciphertext"           : "<base64>",  // Payload terenkripsi Ascon
        "guard_id"             : "<string>"   // ID Petugas (= Associated Data Ascon)
    }

    Alur Dekripsi:
      FASE 1 — Key Unwrapping:
        ECDH → shared_secret → HKDF → KEK → AES-GCM-Decrypt → ascon_session_key

      FASE 2 — Payload Decryption:
        Ascon-AEAD128-Decrypt(ascon_session_key, ciphertext, guard_id) → JSON

      FASE 3 — Storage:
        Parse JSON array → INSERT setiap entri ke tabel gate_logs
    """
    data = request.json

    # Validasi field
    required = [
        'ephemeral_public_key', 'encrypted_ascon_key', 'key_iv',
        'ascon_nonce', 'ciphertext', 'guard_id'
    ]
    for field in required:
        if field not in data:
            return jsonify({"status": "error", "message": f"Missing: {field}"}), 400

    try:
        # Decode semua nilai Base64
        eph_pub   = base64.b64decode(data['ephemeral_public_key'])
        enc_key   = base64.b64decode(data['encrypted_ascon_key'])
        key_iv    = base64.b64decode(data['key_iv'])
        a_nonce   = base64.b64decode(data['ascon_nonce'])
        ct        = base64.b64decode(data['ciphertext'])
        guard_id  = data['guard_id']

        # ════════════════════════════════════════════════════
        # FASE 1: Dekripsi Kunci Sesi Ascon (ECDH + AES-GCM)
        # ════════════════════════════════════════════════════
        ascon_key = decrypt_ascon_key(eph_pub, enc_key, key_iv)

        # ════════════════════════════════════════════════════
        # FASE 2: Dekripsi Payload JSON (Ascon-AEAD128)
        # ════════════════════════════════════════════════════
        # guard_id digunakan sebagai Associated Data (AD).
        # Ini mengikat ciphertext secara kriptografis ke petugas tertentu —
        # mencegah serangan substitusi payload antar-petugas.
        ad = guard_id.encode('utf-8')
        plaintext_json = ascon_decrypt_payload(ascon_key, a_nonce, ad, ct)

        # ════════════════════════════════════════════════════
        # FASE 3: Parse & Simpan ke Database
        # ════════════════════════════════════════════════════
        entries = json.loads(plaintext_json)
        if not isinstance(entries, list):
            entries = [entries]

        conn = get_db()
        count = 0

        for entry in entries:
            if 'nama_mahasiswa' not in entry or 'tujuan' not in entry:
                continue
            conn.execute(
                """INSERT INTO gate_logs (guard_id, nama_mahasiswa, tujuan, estimasi_kembali)
                   VALUES (?, ?, ?, ?)""",
                (
                    guard_id,
                    entry['nama_mahasiswa'],
                    entry['tujuan'],
                    entry.get('estimasi_kembali', '-')
                )
            )
            count += 1

        # Catat di audit log
        conn.execute(
            "INSERT INTO audit_logs (guard_id, action, entry_count) VALUES (?, ?, ?)",
            (guard_id, f"Submitted {count} encrypted entry/entries (Ascon-AEAD128)", count)
        )
        conn.commit()
        conn.close()

        return jsonify({
            "status": "success",
            "message": f"{count} entri berhasil disimpan secara terenkripsi.",
            "count": count
        }), 200

    except ValueError as e:
        # Gagal dekripsi / verifikasi tag Ascon
        return jsonify({"status": "error", "message": str(e)}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": f"Server error: {str(e)}"}), 500


# ============================================================
# API Routes — Data Management (CRUD)
# ============================================================

@app.route('/api/get_entries', methods=['GET'])
def get_entries():
    """Mengambil semua log keluar-masuk."""
    conn = get_db()
    rows = conn.execute("SELECT * FROM gate_logs ORDER BY timestamp DESC").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route('/api/get_students', methods=['GET'])
def get_students():
    """Kompatibilitas — mengembalikan array kosong (data sekarang diinput manual)."""
    return jsonify([])


@app.route('/api/delete_entry/<int:entry_id>', methods=['DELETE'])
def delete_entry(entry_id):
    """Menghapus satu entri log."""
    conn = get_db()
    entry = conn.execute("SELECT * FROM gate_logs WHERE id = ?", (entry_id,)).fetchone()
    if entry:
        conn.execute(
            "INSERT INTO audit_logs (guard_id, action) VALUES (?, ?)",
            (entry['guard_id'], f"Deleted: {entry['nama_mahasiswa']}")
        )
        conn.execute("DELETE FROM gate_logs WHERE id = ?", (entry_id,))
        conn.commit()
        conn.close()
        return jsonify({"status": "success"}), 200
    conn.close()
    return jsonify({"status": "error", "message": "Not found"}), 404


@app.route('/api/delete_all_entries', methods=['DELETE'])
def delete_all_entries():
    """Menghapus semua entri log."""
    try:
        conn = get_db()
        conn.execute(
            "INSERT INTO audit_logs (guard_id, action) VALUES (?, ?)",
            ("SYSTEM", "All gate logs cleared")
        )
        conn.execute("DELETE FROM gate_logs")
        conn.commit()
        conn.close()
        return jsonify({"status": "success"}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/get_audit_logs', methods=['GET'])
def get_audit_logs():
    """Mengambil semua log audit."""
    conn = get_db()
    rows = conn.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


# ============================================================
# Entry Point
# ============================================================

if __name__ == '__main__':
    app.run(debug=True, port=5000)
