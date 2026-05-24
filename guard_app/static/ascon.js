/**
 * ascon.js — Ascon-AEAD128 (Ascon-128) Lightweight Authenticated Encryption
 * ==========================================================================
 * Implementasi murni JavaScript dari algoritma Ascon-128 AEAD.
 * Setara dengan NIST Lightweight Cryptography Standard (Ascon-AEAD128).
 *
 * Spesifikasi Kriptografi:
 *   Key   : 128 bit  (16 bytes)
 *   Nonce : 128 bit  (16 bytes)
 *   Tag   : 128 bit  (16 bytes)
 *   Rate  :  64 bit  ( 8 bytes)
 *   Rounds: a=12 (init/final), b=6 (processing)
 *
 * Referensi: https://ascon.iaik.tugraz.at/
 * Author  : Satria Tegar Bimantara
 */

const AsconAEAD128 = (() => {
    "use strict";

    // ==================== Konstanta ====================
    const RATE    = 8;                       // Rate dalam bytes (64 bit)
    const IV      = 0x80400c0600000000n;     // Initialization Vector Ascon-128
    const MASK64  = (1n << 64n) - 1n;        // Mask 64-bit
    const ROUNDS  = [                        // Konstanta ronde (12 ronde)
        0xf0n, 0xe1n, 0xd2n, 0xc3n, 0xb4n, 0xa5n,
        0x96n, 0x87n, 0x78n, 0x69n, 0x5an, 0x4bn
    ];

    // ==================== Utilitas ====================

    /** Konversi 8 bytes (big-endian) menjadi BigInt 64-bit */
    function bytesToU64(buf, off) {
        let v = 0n;
        for (let i = 0; i < 8; i++) v = (v << 8n) | BigInt(buf[off + i] || 0);
        return v;
    }

    /** Konversi BigInt 64-bit menjadi 8 bytes (big-endian) */
    function u64ToBytes(v, out, off) {
        for (let i = 7; i >= 0; i--) { out[off + i] = Number(v & 0xffn); v >>= 8n; }
    }

    /** Rotasi kanan 64-bit */
    function rotr(x, n) {
        const bn = BigInt(n);
        return ((x >> bn) | (x << (64n - bn))) & MASK64;
    }

    // ==================== Permutasi Ascon ====================

    /**
     * [CRYPTO] Permutasi inti Ascon pada state 320-bit (5 × 64-bit words).
     * Terdiri dari 3 lapisan per ronde:
     *   pC — Penambahan konstanta ronde
     *   pS — Lapisan substitusi (S-box 5-bit, diterapkan bitwise paralel)
     *   pL — Lapisan difusi linear (rotasi + XOR)
     */
    function permutation(S, rounds) {
        for (let r = 12 - rounds; r < 12; r++) {
            // ── pC: Penambahan Konstanta Ronde ──
            S[2] ^= ROUNDS[r];

            // ── pS: Lapisan Substitusi (5-bit S-box) ──
            S[0] ^= S[4];  S[4] ^= S[3];  S[2] ^= S[1];
            const T = new Array(5);
            for (let i = 0; i < 5; i++) T[i] = (S[i] ^ MASK64) & S[(i + 1) % 5];
            for (let i = 0; i < 5; i++) S[i] ^= T[(i + 1) % 5];
            S[1] ^= S[0];  S[0] ^= S[4];  S[3] ^= S[2];  S[2] ^= MASK64;
            for (let i = 0; i < 5; i++) S[i] &= MASK64;

            // ── pL: Lapisan Difusi Linear ──
            S[0] ^= rotr(S[0], 19) ^ rotr(S[0], 28);
            S[1] ^= rotr(S[1], 61) ^ rotr(S[1], 39);
            S[2] ^= rotr(S[2],  1) ^ rotr(S[2],  6);
            S[3] ^= rotr(S[3], 10) ^ rotr(S[3], 17);
            S[4] ^= rotr(S[4],  7) ^ rotr(S[4], 41);
            for (let i = 0; i < 5; i++) S[i] &= MASK64;
        }
    }

    // ==================== AEAD Encrypt ====================

    /**
     * [CRYPTO] Ascon-AEAD128 Authenticated Encryption.
     *
     * @param {Uint8Array} key   — Kunci 16 bytes
     * @param {Uint8Array} nonce — Nonce 16 bytes (HARUS unik per enkripsi)
     * @param {Uint8Array} ad    — Associated Data (diautentikasi, tidak dienkripsi)
     * @param {Uint8Array} pt    — Plaintext yang akan dienkripsi
     * @returns {Uint8Array}       Ciphertext || Tag (panjang = pt.length + 16)
     */
    function encrypt(key, nonce, ad, pt) {
        if (key.length !== 16) throw new Error("Key harus 16 bytes");
        if (nonce.length !== 16) throw new Error("Nonce harus 16 bytes");

        const K = [bytesToU64(key, 0), bytesToU64(key, 8)];
        const N = [bytesToU64(nonce, 0), bytesToU64(nonce, 8)];

        // ── Inisialisasi State: IV ‖ K ‖ N (320 bit) ──
        const S = [IV, K[0], K[1], N[0], N[1]];
        permutation(S, 12);                          // Permutasi inisialisasi (a=12)
        S[3] = (S[3] ^ K[0]) & MASK64;
        S[4] = (S[4] ^ K[1]) & MASK64;

        // ── Proses Associated Data ──
        if (ad && ad.length > 0) {
            let i;
            for (i = 0; i + RATE <= ad.length; i += RATE) {
                S[0] = (S[0] ^ bytesToU64(ad, i)) & MASK64;
                permutation(S, 6);                   // Permutasi intermediate (b=6)
            }
            // Blok terakhir + padding 10*
            const pad = new Uint8Array(RATE);
            const rem = ad.length - i;
            if (rem > 0) pad.set(ad.slice(i, i + rem));
            pad[rem] = 0x80;
            S[0] = (S[0] ^ bytesToU64(pad, 0)) & MASK64;
            permutation(S, 6);
        }
        S[4] = (S[4] ^ 1n) & MASK64;                // Domain separation

        // ── Proses Plaintext → Ciphertext ──
        const ct = new Uint8Array(pt.length + 16);   // +16 untuk tag autentikasi
        let i;
        for (i = 0; i + RATE <= pt.length; i += RATE) {
            S[0] = (S[0] ^ bytesToU64(pt, i)) & MASK64;
            u64ToBytes(S[0], ct, i);                 // Ekstrak blok ciphertext
            permutation(S, 6);
        }
        // Blok terakhir (parsial) + padding
        const rem = pt.length - i;
        const pad = new Uint8Array(RATE);
        if (rem > 0) pad.set(pt.slice(i, i + rem));
        pad[rem] = 0x80;
        S[0] = (S[0] ^ bytesToU64(pad, 0)) & MASK64;
        const blk = new Uint8Array(RATE);
        u64ToBytes(S[0], blk, 0);
        for (let j = 0; j < rem; j++) ct[i + j] = blk[j];

        // ── Finalisasi: menghasilkan Tag Autentikasi 128-bit ──
        S[1] = (S[1] ^ K[0]) & MASK64;
        S[2] = (S[2] ^ K[1]) & MASK64;
        permutation(S, 12);                          // Permutasi finalisasi (a=12)
        u64ToBytes((S[3] ^ K[0]) & MASK64, ct, pt.length);
        u64ToBytes((S[4] ^ K[1]) & MASK64, ct, pt.length + 8);

        return ct;
    }

    // ==================== AEAD Decrypt ====================

    /**
     * [CRYPTO] Ascon-AEAD128 Authenticated Decryption.
     *
     * @param {Uint8Array} key   — Kunci 16 bytes
     * @param {Uint8Array} nonce — Nonce 16 bytes
     * @param {Uint8Array} ad    — Associated Data
     * @param {Uint8Array} ctTag — Ciphertext || Tag (minimal 16 bytes)
     * @returns {Uint8Array|null}  Plaintext, atau null jika tag tidak valid
     */
    function decrypt(key, nonce, ad, ctTag) {
        if (key.length !== 16) throw new Error("Key harus 16 bytes");
        if (nonce.length !== 16) throw new Error("Nonce harus 16 bytes");
        if (ctTag.length < 16) throw new Error("Input terlalu pendek");

        const ctLen = ctTag.length - 16;
        const ct  = ctTag.slice(0, ctLen);
        const tag = ctTag.slice(ctLen);

        const K = [bytesToU64(key, 0), bytesToU64(key, 8)];
        const N = [bytesToU64(nonce, 0), bytesToU64(nonce, 8)];

        const S = [IV, K[0], K[1], N[0], N[1]];
        permutation(S, 12);
        S[3] = (S[3] ^ K[0]) & MASK64;
        S[4] = (S[4] ^ K[1]) & MASK64;

        // Proses AD (identik dengan encrypt)
        if (ad && ad.length > 0) {
            let i;
            for (i = 0; i + RATE <= ad.length; i += RATE) {
                S[0] = (S[0] ^ bytesToU64(ad, i)) & MASK64;
                permutation(S, 6);
            }
            const pad = new Uint8Array(RATE);
            const rem = ad.length - i;
            if (rem > 0) pad.set(ad.slice(i, i + rem));
            pad[rem] = 0x80;
            S[0] = (S[0] ^ bytesToU64(pad, 0)) & MASK64;
            permutation(S, 6);
        }
        S[4] = (S[4] ^ 1n) & MASK64;

        // Dekripsi Ciphertext → Plaintext
        const pt = new Uint8Array(ctLen);
        let i;
        for (i = 0; i + RATE <= ctLen; i += RATE) {
            const cBlk = bytesToU64(ct, i);
            u64ToBytes((S[0] ^ cBlk) & MASK64, pt, i);  // Ekstrak plaintext
            S[0] = cBlk;                                  // Ganti state dengan ciphertext
            permutation(S, 6);
        }
        // Blok terakhir (parsial)
        const rem = ctLen - i;
        const sBytes = new Uint8Array(RATE);
        u64ToBytes(S[0], sBytes, 0);
        for (let j = 0; j < rem; j++) pt[i + j] = sBytes[j] ^ ct[i + j];
        // Rekonstruksi state
        for (let j = 0; j < rem; j++) sBytes[j] = ct[i + j];
        sBytes[rem] ^= 0x80;
        S[0] = bytesToU64(sBytes, 0);

        // Finalisasi + Verifikasi Tag
        S[1] = (S[1] ^ K[0]) & MASK64;
        S[2] = (S[2] ^ K[1]) & MASK64;
        permutation(S, 12);
        const t = new Uint8Array(16);
        u64ToBytes((S[3] ^ K[0]) & MASK64, t, 0);
        u64ToBytes((S[4] ^ K[1]) & MASK64, t, 8);

        // [CRYPTO] Perbandingan tag konstan-waktu (constant-time comparison)
        let diff = 0;
        for (let j = 0; j < 16; j++) diff |= t[j] ^ tag[j];
        return diff === 0 ? pt : null;
    }

    return { encrypt, decrypt };
})();
