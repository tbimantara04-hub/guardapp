document.addEventListener('DOMContentLoaded', () => {
    const loginForm = document.getElementById('loginForm');
    const loginBtn = document.getElementById('loginBtn');
    const spinner = document.getElementById('spinner');
    const btnText = document.querySelector('.btn-text');
    const errorMsg = document.getElementById('errorMsg');

    // Fetch server public key
    let serverPublicKey = null;

    async function fetchPublicKey() {
        try {
            const res = await fetch('/api/get_public_key');
            if (res.ok) {
                const pem = await res.text();
                serverPublicKey = forge.pki.publicKeyFromPem(pem);
            } else {
                console.error("Gagal mendapatkan public key");
            }
        } catch (e) {
            console.error("Error fetching public key:", e);
        }
    }

    fetchPublicKey();

    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        if (!serverPublicKey) {
            alert("Sedang mengambil kunci keamanan server. Coba lagi dalam beberapa detik.");
            return;
        }

        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;

        loginBtn.disabled = true;
        spinner.style.display = 'block';
        btnText.style.opacity = '0';
        errorMsg.style.display = 'none';

        try {
            // Encrypt credentials with RSA
            const credentials = { username, password };
            const jsonString = JSON.stringify(credentials);
            
            // Encrypt with RSA public key
            const encryptedBytes = serverPublicKey.encrypt(jsonString, 'RSA-OAEP', {
                md: forge.md.sha256.create(),
                mgf1: {
                    md: forge.md.sha256.create()
                }
            });
            
            const encryptedCredentials = forge.util.encode64(encryptedBytes);

            const res = await fetch('/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ credentials: encryptedCredentials })
            });

            const data = await res.json();

            if (res.ok && data.status === 'success') {
                localStorage.setItem('auth_token', data.token);
                localStorage.setItem('auth_user', data.username);
                window.location.href = '/';
            } else {
                errorMsg.textContent = data.message || "Username atau password salah.";
                errorMsg.style.display = 'block';
            }
        } catch (error) {
            console.error("Login Error:", error);
            errorMsg.textContent = "Terjadi kesalahan pada server.";
            errorMsg.style.display = 'block';
        } finally {
            loginBtn.disabled = false;
            spinner.style.display = 'none';
            btnText.style.opacity = '1';
        }
    });
});
