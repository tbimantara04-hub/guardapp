-- ============================================================
-- Guard App - Database Schema
-- Lightweight Hybrid Cryptography (ECC secp256r1 + Ascon-AEAD128)
-- Author: Satria Tegar Bimantara
-- ============================================================

-- Tabel utama: log keluar-masuk mahasiswa
CREATE TABLE IF NOT EXISTS gate_logs (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    guard_id          TEXT    NOT NULL,
    nama_mahasiswa    TEXT    NOT NULL,
    tujuan            TEXT    NOT NULL,
    estimasi_kembali  TEXT    NOT NULL,
    timestamp         DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Tabel jejak audit (audit trail)
CREATE TABLE IF NOT EXISTS audit_logs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    guard_id      TEXT    NOT NULL,
    action        TEXT    NOT NULL,
    entry_count   INTEGER DEFAULT 1,
    timestamp     DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Tabel autentikasi pengguna (petugas keamanan)
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    UNIQUE NOT NULL,
    password_hash TEXT    NOT NULL
);

-- Index untuk optimasi query
CREATE INDEX IF NOT EXISTS idx_gate_logs_guard     ON gate_logs(guard_id);
CREATE INDEX IF NOT EXISTS idx_gate_logs_timestamp ON gate_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);
