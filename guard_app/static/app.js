async function getPublicKey() {
    const response = await fetch('/api/get_public_key');
    return await response.text();
}

function generateFernetKey() {
    // Fernet key is 32 bytes, base64url encoded
    const key = forge.random.getBytesSync(32);
    return btoa(key).replace(/\+/g, '-').replace(/\//g, '_');
}

function encryptWithFernet(keyB64, plaintext) {
    // Fernet Spec: https://github.com/fernet/spec/blob/master/Spec.md
    // Version (1 byte) | Timestamp (8 bytes) | IV (16 bytes) | Ciphertext (variable) | HMAC (32 bytes)
    
    const key = forge.util.decode64(keyB64.replace(/-/g, '+').replace(/_/g, '/'));
    const signingKey = key.slice(0, 16);
    const encryptionKey = key.slice(16, 32);

    const version = forge.util.hexToBytes('80');
    
    // Timestamp (8 bytes, big-endian)
    const timestamp = Math.floor(Date.now() / 1000);
    const tsHex = timestamp.toString(16).padStart(16, '0');
    const tsBytes = forge.util.hexToBytes(tsHex);

    // IV (16 bytes)
    const iv = forge.random.getBytesSync(16);

    // Encrypt (AES-128-CBC)
    const cipher = forge.cipher.createCipher('AES-CBC', encryptionKey);
    cipher.start({iv: iv});
    cipher.update(forge.util.createBuffer(plaintext, 'utf8'));
    cipher.finish();
    const ciphertext = cipher.output.getBytes();

    // HMAC (SHA256)
    const hmac = forge.hmac.create();
    hmac.start('sha256', signingKey);
    const dataToSign = version + tsBytes + iv + ciphertext;
    hmac.update(dataToSign);
    const signature = hmac.digest().getBytes();

    // Combine and Base64URL
    const token = version + tsBytes + iv + ciphertext + signature;
    return btoa(token).replace(/\+/g, '-').replace(/\//g, '_');
}

async function encryptKeyWithRSA(publicKeyPEM, symmetricKey) {
    const publicKey = forge.pki.publicKeyFromPem(publicKeyPEM);
    const encrypted = publicKey.encrypt(symmetricKey, 'RSA-OAEP', {
        md: forge.md.sha256.create(),
        mgf1: {
            md: forge.md.sha256.create()
        }
    });
    return forge.util.encode64(encrypted);
}

const form = document.getElementById('entryForm');
const submitBtn = document.getElementById('submitBtn');
const toast = document.getElementById('toast');
const npmSelect = document.getElementById('npm_select');
const toggleModeBtn = document.getElementById('toggleModeBtn');
const massalHelp = document.getElementById('massal_help');
const pageSubtitle = document.querySelector('header p');

let isMassalMode = false;

if (toggleModeBtn) {
    toggleModeBtn.addEventListener('click', () => {
        isMassalMode = !isMassalMode;
        if (isMassalMode) {
            npmSelect.multiple = true;
            npmSelect.classList.add('massal-mode');
            toggleModeBtn.textContent = '🔄 Beralih ke Keluar Individu';
            
            const isTouch = ('ontouchstart' in window) || (navigator.maxTouchPoints > 0);
            massalHelp.textContent = isTouch 
                ? "*Ketuk beberapa nama untuk memilih lebih dari satu mahasiswa (Keluar Massal)" 
                : "*Tahan tombol CTRL (atau klik-seret) untuk memilih lebih dari satu mahasiswa (Keluar Massal)";
            
            massalHelp.style.display = 'block';
            pageSubtitle.textContent = 'Input Data Keluar Mahasiswa (Massal / Izin Massal)';
        } else {
            npmSelect.multiple = false;
            npmSelect.classList.remove('massal-mode');
            toggleModeBtn.textContent = '🔄 Beralih ke Keluar Massal';
            massalHelp.style.display = 'none';
            pageSubtitle.textContent = 'Input data mahasiswa keluar kampus (Individu)';
            
            if (npmSelect.selectedIndex !== -1) {
                const firstSelected = npmSelect.selectedIndex;
                npmSelect.selectedIndex = -1;
                npmSelect.selectedIndex = firstSelected;
            }
        }
    });
}

function showToast(message, type = 'success') {
    toast.textContent = message;
    toast.className = `toast show ${type}`;
    setTimeout(() => {
        toast.className = 'toast';
    }, 4000);
}

// Load students into dropdown
async function loadStudents() {
    if (!npmSelect) return;
    try {
        const res = await fetch('/api/get_students');
        const students = await res.json();
        
        // Sort students by NPM (ascending/terkecil ke terbesar)
        students.sort((a, b) => String(a.npm).localeCompare(String(b.npm), undefined, {numeric: true}));
        
        npmSelect.innerHTML = ''; 
        
        const defaultOpt = document.createElement('option');
        defaultOpt.value = "";
        defaultOpt.disabled = true;
        defaultOpt.selected = true;
        defaultOpt.textContent = "Pilih Mahasiswa...";
        npmSelect.appendChild(defaultOpt);

        students.forEach(s => {
            const opt = document.createElement('option');
            opt.value = s.npm;
            opt.dataset.name = s.name;
            opt.textContent = `${s.npm} - ${s.name}`;
            npmSelect.appendChild(opt);
        });
    } catch (err) {
        console.error("Gagal memuat data mahasiswa", err);
        npmSelect.innerHTML = '<option disabled>Gagal memuat database</option>';
    }
}
loadStudents();

form.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    submitBtn.classList.add('loading');
    submitBtn.disabled = true;

    try {
        const guard_id = document.getElementById('guard_id').value;
        const keterangan = document.getElementById('keterangan').value;

        // Get all selected options
        const selectedOptions = Array.from(npmSelect.selectedOptions).filter(opt => opt.value !== "");
        
        if (selectedOptions.length === 0) {
            showToast("Pilih minimal 1 mahasiswa!", "error");
            submitBtn.classList.remove('loading');
            submitBtn.disabled = false;
            return;
        }

        // Create array of students
        const payloadArray = selectedOptions.map(opt => ({
            npm: opt.value,
            name: opt.dataset.name,
            keterangan: keterangan
        }));

        const studentData = JSON.stringify(payloadArray);

        // 1. Get Server Public Key
        const publicKeyPEM = await getPublicKey();

        // 2. Generate Symmetric (Fernet) Key
        const symKey = generateFernetKey();

        // 3. Encrypt Data with Fernet
        const encryptedData = encryptWithFernet(symKey, studentData);

        // 4. Encrypt Symmetric Key with RSA
        const encryptedKey = await encryptKeyWithRSA(publicKeyPEM, symKey);

        // 5. Send to Server
        const response = await fetch('/api/submit_entry', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                payload: encryptedData,
                key: encryptedKey,
                guard_id: guard_id
            })
        });

        const result = await response.json();

        if (response.ok) {
            if (payloadArray.length > 1) {
                showToast(`Data ${payloadArray.length} mahasiswa (Izin Massal) berhasil dikirim dan terenkripsi!`, 'success');
            } else {
                showToast(`Data a.n. ${payloadArray[0].name} berhasil dikirim dan terenkripsi!`, 'success');
            }
            // Reset selects but keep Guard ID
            npmSelect.selectedIndex = 0;
            document.getElementById('keterangan').selectedIndex = 0;
        } else {
            showToast('Gagal: ' + result.message, 'error');
        }

    } catch (error) {
        console.error(error);
        showToast('Terjadi kesalahan sistem', 'error');
    } finally {
        submitBtn.classList.remove('loading');
        submitBtn.disabled = false;
    }
});
