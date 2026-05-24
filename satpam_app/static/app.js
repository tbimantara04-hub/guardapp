async function getPublicKey() {
    const response = await fetch('/api/get_public_key');
    if (!response.ok) throw new Error("Gagal mengambil Public Key dari server");
    return await response.text();
}

function generateFernetKey() {
    const keyBytes = forge.random.getBytesSync(32);
    return btoa(keyBytes).replace(/\+/g, '-').replace(/\//g, '_');
}

function encryptDataFernet(keyB64, plaintext) {
    const keyStr = forge.util.decode64(keyB64.replace(/-/g, '+').replace(/_/g, '/'));
    const signKey = keyStr.slice(0, 16);
    const encKey = keyStr.slice(16, 32);

    const version = forge.util.hexToBytes('80');
    const ts = Math.floor(Date.now() / 1000);
    const tsHex = ts.toString(16).padStart(16, '0');
    const tsBytes = forge.util.hexToBytes(tsHex);

    const iv = forge.random.getBytesSync(16);

    const cipher = forge.cipher.createCipher('AES-CBC', encKey);
    cipher.start({ iv: iv });
    cipher.update(forge.util.createBuffer(plaintext, 'utf8'));
    cipher.finish();
    const ciphertext = cipher.output.getBytes();

    const hmac = forge.hmac.create();
    hmac.start('sha256', signKey);
    hmac.update(version + tsBytes + iv + ciphertext);
    const signature = hmac.digest().getBytes();

    const token = version + tsBytes + iv + ciphertext + signature;
    return btoa(token).replace(/\+/g, '-').replace(/\//g, '_');
}

async function encryptKeyRSA(publicKeyPEM, symmetricKey) {
    const publicKey = forge.pki.publicKeyFromPem(publicKeyPEM);
    const encrypted = publicKey.encrypt(symmetricKey, 'RSA-OAEP', {
        md: forge.md.sha256.create(),
        mgf1: { md: forge.md.sha256.create() }
    });
    return forge.util.encode64(encrypted);
}

const form = document.getElementById('entryForm');
const submitBtn = document.getElementById('submitBtn');
const toast = document.getElementById('toast');
const npmSelect = document.getElementById('npm_select');
const toggleModeBtn = document.getElementById('toggleModeBtn');
const massalHelp = document.getElementById('massal_help');
const pageSubtitle = document.getElementById('page_subtitle');

let isMassalMode = false;

if(toggleModeBtn) {
    toggleModeBtn.addEventListener('click', () => {
        isMassalMode = !isMassalMode;
        if(isMassalMode) {
            npmSelect.multiple = true;
            npmSelect.classList.add('massal-mode');
            toggleModeBtn.textContent = '🔄 Beralih ke Keluar Individu';
            
            // Adjust help text based on device
            const isTouch = ('ontouchstart' in window) || (navigator.maxTouchPoints > 0);
            massalHelp.textContent = isTouch 
                ? "*Ketuk beberapa nama untuk memilih lebih dari satu mahasiswa (Keluar Massal)" 
                : "*Tahan tombol CTRL untuk memilih lebih dari satu mahasiswa (Keluar Massal)";
            
            massalHelp.style.display = 'block';
            pageSubtitle.textContent = 'Input Data Keluar Mahasiswa (Massal)';
        } else {
            npmSelect.multiple = false;
            npmSelect.classList.remove('massal-mode');
            toggleModeBtn.textContent = '🔄 Beralih ke Keluar Massal';
            massalHelp.style.display = 'none';
            pageSubtitle.textContent = 'Input Data Keluar Mahasiswa (Individu)';
            
            // Reset selection to the first selected item to avoid visual bugs
            if(npmSelect.selectedIndex !== -1) {
                const firstSelected = npmSelect.selectedIndex;
                npmSelect.selectedIndex = -1;
                npmSelect.selectedIndex = firstSelected;
            }
        }
    });
}

function showToast(msg, type='success') {
    toast.textContent = msg;
    toast.className = `toast show ${type}`;
    setTimeout(() => { toast.className = 'toast'; }, 4000);
}

// Load students into dropdown
async function loadStudents() {
    if(!npmSelect) return;
    try {
        const res = await fetch('/api/get_students');
        const students = await res.json();
        
        // Remove "Memuat data..." option
        npmSelect.innerHTML = ''; 
        
        // Add a default empty option for individu mode
        const defaultOpt = document.createElement('option');
        defaultOpt.value = "";
        defaultOpt.disabled = true;
        defaultOpt.selected = true;
        defaultOpt.textContent = "Pilih Mahasiswa...";
        npmSelect.appendChild(defaultOpt);

        students.forEach(s => {
            const opt = document.createElement('option');
            opt.value = s.npm;
            opt.dataset.name = s.nama;
            opt.textContent = `${s.npm} - ${s.nama}`;
            npmSelect.appendChild(opt);
        });
    } catch(err) {
        console.error("Gagal memuat data mahasiswa", err);
        npmSelect.innerHTML = '<option disabled>Gagal memuat database</option>';
    }
}
loadStudents();

if(form) {
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        submitBtn.classList.add('loading');
        submitBtn.disabled = true;

        try {
            const guard_id = document.getElementById('guard_id').value;
            const keterangan = document.getElementById('keterangan').value;
            
            // Get all selected options
            const selectedOptions = Array.from(npmSelect.selectedOptions).filter(opt => opt.value !== "");
            
            if(selectedOptions.length === 0) {
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

            const payloadData = JSON.stringify(payloadArray);

            const pubKeyPEM = await getPublicKey();
            const symKey = generateFernetKey();
            const encryptedPayload = encryptDataFernet(symKey, payloadData);
            const encryptedKey = await encryptKeyRSA(pubKeyPEM, symKey);

            const res = await fetch('/api/submit_entry', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    payload: encryptedPayload,
                    key: encryptedKey,
                    guard_id: guard_id
                })
            });

            const result = await res.json();
            if(res.ok) {
                if(payloadArray.length > 1) {
                    showToast(`Berhasil! Data ${payloadArray.length} mahasiswa terkirim.`, "success");
                } else {
                    showToast(`Berhasil! Data a.n. ${payloadArray[0].name} terkirim.`, "success");
                }
                
                // Only reset the student selection & keterangan, keep guard ID
                npmSelect.selectedIndex = 0;
                document.getElementById('keterangan').selectedIndex = 0;
                
            } else {
                showToast("Gagal: " + result.message, "error");
            }
        } catch (error) {
            console.error(error);
            showToast("Terjadi kesalahan sistem (Lihat Console)", "error");
        } finally {
            submitBtn.classList.remove('loading');
            submitBtn.disabled = false;
        }
    });
}
