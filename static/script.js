const API_BASE = '/api';
let TOKEN = localStorage.getItem('vault_token');

// Elements
const views = {
    login: document.getElementById('login-view'),
    register: document.getElementById('register-view'),
    modeSelect: document.getElementById('mode-select-view'),
    deterministic: document.getElementById('deterministic-view'),
    vault: document.getElementById('vault-view'),
    mfa: document.getElementById('mfa-view')
};
const forms = {
    login: document.getElementById('login-form'),
    register: document.getElementById('register-form'),
    entry: document.getElementById('entry-form'),
    entry: document.getElementById('entry-form'),
    deterministic: document.getElementById('deterministic-form'),
    mfaEnable: document.getElementById('mfa-enable-form')
};
const modals = {
    entry: document.getElementById('entry-modal')
};

// Utils
function showView(viewName) {
    Object.values(views).forEach(el => el.classList.add('hidden'));
    Object.values(views).forEach(el => el.classList.remove('active'));
    views[viewName].classList.remove('hidden');
    views[viewName].classList.add('active');
}

function showMessage(elementId, msg, isError = false) {
    const el = document.getElementById(elementId);
    el.textContent = msg;
    el.className = 'message ' + (isError ? 'error' : 'success');
    setTimeout(() => {
        el.textContent = '';
        el.className = 'message';
    }, 5000);
}

async function apiCall(endpoint, method = 'GET', body = null) {
    const headers = {
        'Content-Type': 'application/json'
    };
    if (TOKEN) {
        headers['Authorization'] = TOKEN;
    }

    const options = {
        method,
        headers,
    };
    if (body) {
        options.body = JSON.stringify(body);
    }

    const res = await fetch(API_BASE + endpoint, options);
    const data = await res.json();

    if (!res.ok) {
        throw new Error(data.error || 'Unknown error');
    }
    return data;
}

// App Logic

async function checkSession() {
    if (!TOKEN) {
        showView('login');
        return;
    }
    try {
        await apiCall('/check-session');
        // If session valid, go to Mode Select instead of straight to Vault
        showView('modeSelect');
        document.getElementById('logout-btn').classList.remove('hidden');
        document.getElementById('connection-status').textContent = 'CONNECTION: ESTABLISHED';
        document.getElementById('connection-status').style.color = 'var(--primary-color)';
    } catch (e) {
        console.log('Session invalid');
        logout();
    }
}

function logout() {
    if (TOKEN) {
        apiCall('/logout', 'POST').catch(() => { });
    }
    TOKEN = null;
    localStorage.removeItem('vault_token');
    document.getElementById('logout-btn').classList.add('hidden');
    document.getElementById('connection-status').textContent = 'CONNECTION: TERMINATED';
    document.getElementById('connection-status').style.color = 'red';
    showView('login');
}

async function handleLogin(e) {
    e.preventDefault();
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const otp = document.getElementById('otp').value;

    try {
        const res = await apiCall('/login', 'POST', { username, password, otp });
        TOKEN = res.token;
        localStorage.setItem('vault_token', TOKEN);
        document.getElementById('username').value = '';
        document.getElementById('password').value = '';
        document.getElementById('otp').value = '';
        document.getElementById('mfa-group').classList.add('hidden');

        // Go to Mode Select
        showView('modeSelect');
        document.getElementById('logout-btn').classList.remove('hidden');
        document.getElementById('connection-status').textContent = 'CONNECTION: ESTABLISHED';
        document.getElementById('connection-status').style.color = 'var(--primary-color)';

    } catch (err) {
        // Check if MFA is required? The backend currently returns 401 with message. 
        // If we want to handle MFA flow nicely we need to parse the error.
        showMessage('login-msg', 'ERROR: ' + err.message, true);
        if (err.message.includes("MFA")) {
            document.getElementById('mfa-group').classList.remove('hidden');
        }
    }
}

async function handleRegister(e) {
    e.preventDefault();
    const username = document.getElementById('reg-username').value;
    const password = document.getElementById('reg-password').value;

    if (password.length < 12) {
        showMessage('reg-msg', 'PASSWORD TOO SHORT (MIN 12)', true);
        return;
    }

    try {
        await apiCall('/register', 'POST', { username, password });
        showMessage('reg-msg', 'IDENTITY CREATED. PROCEED TO AUTH.', false);
        setTimeout(() => {
            showView('login');
            document.getElementById('username').value = username;
        }, 1500);
    } catch (err) {
        showMessage('reg-msg', 'REGISTRATION FAILED: ' + err.message, true);
    }
}

// Mode Selection Handlers
document.getElementById('select-mode-a').onclick = () => {
    showView('deterministic');
    document.getElementById('det-site').focus();
};
document.getElementById('select-mode-b').onclick = () => {
    initVault();
};

document.getElementById('back-to-modes-a').onclick = () => showView('modeSelect');
document.getElementById('back-to-modes-b').onclick = () => showView('modeSelect');
document.getElementById('back-to-modes-mfa').onclick = () => showView('modeSelect');
document.getElementById('tab-mfa-config').onclick = () => initMFA();



// Deterministic Logic
forms.deterministic.addEventListener('submit', async (e) => {
    e.preventDefault();
    const site = document.getElementById('det-site').value;
    const passphrase = document.getElementById('det-passphrase').value;
    const length = document.getElementById('det-length').value;

    try {
        const res = await apiCall('/generate-deterministic', 'POST', { site, passphrase, length });
        document.getElementById('det-result-container').classList.remove('hidden');
        document.getElementById('det-result').textContent = res.password;
        showMessage('det-msg', 'KEY GENERATED. CLICK TO COPY.', false);
    } catch (err) {
        showMessage('det-msg', 'GENERATION FAILED: ' + err.message, true);
    }
});

window.copyResult = () => {
    const text = document.getElementById('det-result').textContent;
    navigator.clipboard.writeText(text);
    showMessage('det-msg', 'COPIED TO CLIPBOARD', false);
};


async function initVault() {
    showView('vault');
    loadVaultEntries();
}

async function loadVaultEntries() {
    try {
        const res = await apiCall('/vault');
        renderVault(res.entries || []);
    } catch (err) {
        console.error(err);
        logout(); // Force logout on invalid session in vault view
    }
}

function renderVault(entries) {
    const tbody = document.getElementById('vault-list');
    tbody.innerHTML = '';

    entries.forEach(entry => {
        const tr = document.createElement('tr');

        const pwdDisplay = document.createElement('span');
        pwdDisplay.className = 'password-display';
        pwdDisplay.textContent = '••••••••••••';
        pwdDisplay.onclick = () => {
            if (pwdDisplay.textContent === '••••••••••••') {
                pwdDisplay.textContent = entry.password;
                setTimeout(() => {
                    pwdDisplay.textContent = '••••••••••••';
                }, 5000);
            } else {
                navigator.clipboard.writeText(entry.password);
                const original = pwdDisplay.textContent;
                pwdDisplay.textContent = '[COPIED]';
                setTimeout(() => {
                    pwdDisplay.textContent = original;
                }, 1000);
            }
        };

        tr.innerHTML = `
            <td>${entry.site}</td>
            <td>${entry.login}</td>
            <td></td> <!-- Password cell -->
            <td>${entry.notes || '-'}</td>
            <td><button class="btn small" onclick="copyUser('${entry.login}')">[CP_USER]</button></td>
        `;
        tr.children[2].appendChild(pwdDisplay);
        tbody.appendChild(tr);
    });
}
window.copyUser = (txt) => {
    navigator.clipboard.writeText(txt);
};

// MFA Logic
async function initMFA() {
    showView('mfa');
    document.getElementById('mfa-msg').textContent = '';
    document.getElementById('mfa-status-text').textContent = 'CHECKING...';
    document.getElementById('mfa-status-text').style.color = 'var(--text-color)';

    try {
        const res = await apiCall('/mfa/status');
        updateMFAUI(res.enabled);
    } catch (err) {
        showMessage('mfa-msg', 'FAILED TO GET STATUS: ' + err.message, true);
    }
}

function updateMFAUI(enabled) {
    const statusText = document.getElementById('mfa-status-text');
    const setupSection = document.getElementById('mfa-setup-section');
    const disableSection = document.getElementById('mfa-disable-section');

    if (enabled) {
        statusText.textContent = 'ENABLED [SECURE]';
        statusText.style.color = 'var(--primary-color)';
        setupSection.classList.add('hidden');
        disableSection.classList.remove('hidden');
    } else {
        statusText.textContent = 'DISABLED [INSECURE]';
        statusText.style.color = 'var(--alert-color)';
        setupSection.classList.remove('hidden');
        disableSection.classList.add('hidden');

        // Reset setup state
        document.getElementById('mfa-seed-display').classList.add('hidden');
        document.getElementById('mfa-enable-form').classList.add('hidden');
        document.getElementById('mfa-verify-otp').value = '';
    }
}

document.getElementById('mfa-generate-btn').onclick = async () => {
    try {
        const res = await apiCall('/mfa/setup', 'POST');
        document.getElementById('mfa-seed-display').classList.remove('hidden');
        document.getElementById('mfa-seed-value').textContent = res.seed;
        document.getElementById('mfa-uri-val').textContent = res.uri;
        document.getElementById('mfa-enable-form').classList.remove('hidden');

        // Scroll to bottom
        document.getElementById('mfa-view').querySelector('.panel').scrollTop = 1000;

        showMessage('mfa-msg', 'KEY GENERATED. ADD TO APP THEN VERIFY.', false);
        document.getElementById('mfa-verify-otp').focus();
    } catch (err) {
        showMessage('mfa-msg', 'GENERATION FAILED: ' + err.message, true);
    }
};

window.copyMFASeed = () => {
    const text = document.getElementById('mfa-seed-value').textContent;
    navigator.clipboard.writeText(text);
    showMessage('mfa-msg', 'COPIED SEED TO CLIPBOARD', false);
};

forms.mfaEnable.addEventListener('submit', async (e) => {
    e.preventDefault();
    const otp = document.getElementById('mfa-verify-otp').value;
    try {
        await apiCall('/mfa/enable', 'POST', { otp });
        showMessage('mfa-msg', 'MFA ENABLED SUCCESSFULLY!', false);
        updateMFAUI(true);
    } catch (err) {
        showMessage('mfa-msg', 'ENABLE FAILED: ' + err.message, true);
    }
});

document.getElementById('mfa-disable-btn').onclick = async () => {
    if (!confirm("Are you sure you want to disable 2FA? This reduces security.")) return;
    try {
        await apiCall('/mfa/disable', 'POST');
        showMessage('mfa-msg', 'MFA DISABLED.', true);
        updateMFAUI(false);
    } catch (err) {
        showMessage('mfa-msg', 'DISABLE FAILED: ' + err.message, true);
    }
};


// Event Listeners
forms.login.addEventListener('submit', handleLogin);
forms.register.addEventListener('submit', handleRegister);

document.getElementById('show-register').onclick = () => showView('register');
document.getElementById('show-login').onclick = () => showView('login');
document.getElementById('logout-btn').onclick = logout;

document.getElementById('add-entry-btn').onclick = () => {
    modals.entry.classList.remove('hidden');
};
document.getElementById('cancel-entry').onclick = () => {
    modals.entry.classList.add('hidden');
};

document.getElementById('gen-pass').onclick = () => {
    const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
    let pwd = "";
    for (let i = 0; i < 16; i++) {
        pwd += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    document.getElementById('new-password').value = pwd;
};

forms.entry.addEventListener('submit', async (e) => {
    e.preventDefault();
    const site = document.getElementById('new-site').value;
    const login = document.getElementById('new-login').value;
    const password = document.getElementById('new-password').value;
    const notes = document.getElementById('new-notes').value;

    try {
        await apiCall('/vault', 'POST', { site, login, password, notes });
        modals.entry.classList.add('hidden');
        forms.entry.reset();
        loadVaultEntries();
    } catch (err) {
        alert("Failed to add entry: " + err.message);
    }
});

document.getElementById('search-box').addEventListener('input', (e) => {
    const term = e.target.value.toLowerCase();
    const rows = document.querySelectorAll('#vault-list tr');
    rows.forEach(row => {
        const text = row.innerText.toLowerCase();
        row.style.display = text.includes(term) ? '' : 'none';
    });
});

// Clock
setInterval(() => {
    const now = new Date();
    document.getElementById('time-display').textContent = now.toLocaleTimeString();
}, 1000);


// Matrix Rain Animation
const canvas = document.getElementById('binary-canvas');
const ctx = canvas.getContext('2d');

canvas.width = window.innerWidth;
canvas.height = window.innerHeight;

const binary = "0100101110";
const fontSize = 14;
const columns = canvas.width / fontSize;

const drops = [];
for (let x = 0; x < columns; x++) {
    drops[x] = 1;
}

function drawMatrix() {
    ctx.fillStyle = "rgba(0, 0, 0, 0.05)";
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    ctx.fillStyle = "#0F0";
    ctx.font = fontSize + "px monospace";

    for (let i = 0; i < drops.length; i++) {
        const text = binary.charAt(Math.floor(Math.random() * binary.length));
        ctx.fillText(text, i * fontSize, drops[i] * fontSize);

        if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
            drops[i] = 0;
        }
        drops[i]++;
    }
}
setInterval(drawMatrix, 33);
window.addEventListener('resize', () => {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
});

// Init
checkSession();
