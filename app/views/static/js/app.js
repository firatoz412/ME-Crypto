// Sunucu bağlantısı (WebSocket ve Polling desteği)
const socket = io({
    transports: ['polling', 'websocket']
});

let currentUser = {
    username: "",
    room: "genel",
    sid: ""
};

let currentHandshake = {
    method: "KYBER",
    status: "NOT_STARTED"
};

let clientSession = {
    aes_key: "KriptoGRAM_Default_AES_Secret_Key_128"
};

let currentAuthMode = "login"; // 'login' veya 'register'

// Sayfa Yüklendiğinde Dinleyicileri Ata
window.addEventListener("DOMContentLoaded", () => {
    // Sohbet mesaj kutusunda Enter dinleyicisi
    const inputMessage = document.getElementById("message-input");
    if (inputMessage) {
        inputMessage.addEventListener("keypress", (e) => {
            if (e.key === "Enter") sendMessage();
        });
    }

    // Giriş modalındaki şifre kutusunda Enter ile o anki sekmeye göre işlem yapma
    const passwordInput = document.getElementById("password-input");
    if (passwordInput) {
        passwordInput.addEventListener("keypress", (e) => {
            if (e.key === "Enter") handleAuthSubmit();
        });
    }

    // Dosya / Resim / PDF seçiciyi bağla
    let fileInput = document.getElementById("file-input");
    if (!fileInput) {
        fileInput = document.createElement("input");
        fileInput.type = "file";
        fileInput.id = "file-input";
        fileInput.style.display = "none";
        document.body.appendChild(fileInput);
    }
    fileInput.accept = "image/*,application/pdf";
    fileInput.addEventListener("change", handleFileUpload);

    const paperclipBtn = document.querySelector(".fa-paperclip")?.parentElement || document.querySelector("i.fa-paperclip");
    if (paperclipBtn) {
        paperclipBtn.style.cursor = "pointer";
        paperclipBtn.onclick = (e) => {
            e.preventDefault();
            fileInput.click();
        };
    }

    const keySelect = document.getElementById("key-select");
    if (keySelect) {
        keySelect.addEventListener("change", (e) => {
            initiateHandshake(e.target.value);
        });
    }

    const modeSelect = document.getElementById("mode-select");
    if (modeSelect) {
        modeSelect.addEventListener("change", (e) => {
            if (e.target.value === "GUVENLI") {
                const currentKey = document.getElementById("key-select")?.value || "KYBER";
                initiateHandshake(currentKey);
            }
        });
    }
});

// Socket Olayları
socket.on("connect", () => {
    const status = document.getElementById("connection-status");
    if (status) {
        status.textContent = "Bağlandı (Çevrimiçi)";
        status.style.color = "#22c55e";
    }
});

socket.on("disconnect", () => {
    const status = document.getElementById("connection-status");
    if (status) {
        status.textContent = "Bağlantı Kesildi";
        status.style.color = "#ef4444";
    }
});

socket.on("connection_response", (data) => {
    currentUser.sid = data.client_id;
    const profileSid = document.getElementById("profile-session-id");
    if (profileSid) profileSid.value = data.client_id;
});

socket.on("handshake_response", (data) => {
    if (data.step === "SERVER_PUB") {
        appendSystemMessage(`[${data.method}] Sunucu Açık Anahtarı Alındı (${data.metrics.pub_size_bytes} byte). El sıkışma tamamlanıyor...`);
        socket.emit("handshake", {
            method: data.method,
            step: "FINALIZE",
            payload: "CLIENT_HANDSHAKE_READY"
        });
    } else if (data.step === "OK") {
        currentHandshake.status = "SECURE";
        currentHandshake.method = data.method;
        
        if (data.aes_key) {
            clientSession.aes_key = data.aes_key;
        } else {
            clientSession.aes_key = CryptoJS.SHA256(data.method + "_SHARED_KEY").toString().substring(0, 32);
        }

        appendSystemMessage(`[✓] ${data.method} ve AES-128 Tüneli Kuruldu! Süre: ${data.metrics.handshake_time_ms} ms`);
    }
});

// Sunucudan oda kullanıcı listesi gelirse otomatik günceller
socket.on("room_users", (users) => {
    updateOnlineList(users);
});

socket.on("receive_message", (data) => {
    renderIncomingMessage(data);
});

// =================== AUTH (GİRİŞ & KAYIT) İŞLEMLERİ ===================

function switchAuthTab(mode) {
    currentAuthMode = mode;
    clearAuthMessages();
    
    const loginTab = document.getElementById("tab-login-btn");
    const registerTab = document.getElementById("tab-register-btn");
    const mainBtn = document.getElementById("auth-main-btn");

    if (mode === "login") {
        if (loginTab) {
            loginTab.style.color = "#38bdf8";
            loginTab.style.borderBottom = "2px solid #38bdf8";
        }
        if (registerTab) {
            registerTab.style.color = "#94a3b8";
            registerTab.style.borderBottom = "2px solid transparent";
        }
        if (mainBtn) mainBtn.textContent = "Giriş Yap";
    } else {
        if (registerTab) {
            registerTab.style.color = "#38bdf8";
            registerTab.style.borderBottom = "2px solid #38bdf8";
        }
        if (loginTab) {
            loginTab.style.color = "#94a3b8";
            loginTab.style.borderBottom = "2px solid transparent";
        }
        if (mainBtn) mainBtn.textContent = "Kayıt Ol ve Giriş Yap";
    }
}

function togglePasswordVisibility() {
    const pwd = document.getElementById("password-input");
    const icon = document.getElementById("toggle-password");
    if (!pwd || !icon) return;

    if (pwd.type === "password") {
        pwd.type = "text";
        icon.classList.remove("fa-eye-slash");
        icon.classList.add("fa-eye");
    } else {
        pwd.type = "password";
        icon.classList.remove("fa-eye");
        icon.classList.add("fa-eye-slash");
    }
}

async function handleAuthSubmit() {
    if (currentAuthMode === "login") {
        await handleLogin();
    } else {
        await handleRegisterAndLogin();
    }
}

async function handleLogin() {
    const username = document.getElementById("username-input")?.value.trim();
    const password = document.getElementById("password-input")?.value.trim();
    const roomSelect = document.getElementById("room-select");

    clearAuthMessages();

    if (!username || !password) {
        showAuthMessage("Lütfen kullanıcı adı ve şifre girin!", "error");
        return;
    }

    try {
        const res = await fetch("/api/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, password })
        });
        const data = await res.json();

        if (data.success) {
            currentUser.username = username;
            currentUser.room = roomSelect ? roomSelect.value : "genel";

            const displayUser = document.getElementById("display-username");
            if (displayUser) displayUser.textContent = username;

            const avatar = document.getElementById("my-avatar");
            if (avatar) avatar.textContent = username.charAt(0).toUpperCase();

            const roomBadge = document.getElementById("current-room-badge");
            if (roomBadge && roomSelect) roomBadge.textContent = roomSelect.options[roomSelect.selectedIndex].text;

            const profInput = document.getElementById("profile-username-input");
            if (profInput) profInput.value = username;

            // Modalı gizle
            const modal = document.getElementById("login-modal");
            if (modal) modal.style.display = "none";

            // Odaya katıl ve soket bildirimi gönder
            socket.emit("join", {
                username: currentUser.username,
                room: currentUser.room
            });

            updateOnlineList([currentUser.username]);

            // Güvenli anahtar el sıkışmasını başlat
            const keySel = document.getElementById("key-select");
            initiateHandshake(keySel ? keySel.value : "KYBER");
        } else {
            showAuthMessage(data.message || "Giriş başarısız!", "error");
        }
    } catch (err) {
        showAuthMessage("Sunucuya bağlanılamadı!", "error");
    }
}

// Kayıt Ol + Başarılı olursa otomatik giriş yap
async function handleRegisterAndLogin() {
    const username = document.getElementById("username-input")?.value.trim();
    const password = document.getElementById("password-input")?.value.trim();

    clearAuthMessages();

    if (!username || !password) {
        showAuthMessage("Kayıt için kullanıcı adı ve şifre giriniz!", "error");
        return;
    }

    try {
        const res = await fetch("/api/register", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, password })
        });
        const data = await res.json();

        if (data.success) {
            showAuthMessage("Hesap oluşturuldu, odaya bağlanılıyor...", "success");
            // Kullanıcıyı bekletmeden otomatik içeri al
            setTimeout(() => {
                handleLogin();
            }, 600);
        } else {
            showAuthMessage(data.message || "Kayıt başarısız!", "error");
        }
    } catch (err) {
        showAuthMessage("Sunucuya bağlanılamadı!", "error");
    }
}

function showAuthMessage(msg, type) {
    const errBox = document.getElementById("auth-error-msg");
    const succBox = document.getElementById("auth-success-msg");

    if (type === "error" && errBox) {
        errBox.textContent = msg;
        errBox.style.display = "block";
    } else if (type === "success" && succBox) {
        succBox.textContent = msg;
        succBox.style.display = "block";
    }
}

function clearAuthMessages() {
    const errBox = document.getElementById("auth-error-msg");
    const succBox = document.getElementById("auth-success-msg");
    if (errBox) errBox.style.display = "none";
    if (succBox) succBox.style.display = "none";
}

// =================== ODA VE KULLANICI LİSTESİ ===================

function updateOnlineList(users) {
    const list = document.getElementById("online-users-list");
    const count = document.getElementById("user-count");
    if (!list) return;

    if (!Array.isArray(users) || users.length === 0) {
        users = [currentUser.username || "Sen"];
    }

    list.innerHTML = "";
    users.forEach(u => {
        const isMe = u === currentUser.username;
        const li = document.createElement("li");
        li.innerHTML = `<i class="fa-solid fa-circle" style="color: #22c55e; font-size: 8px;"></i> ${escapeHtml(u)} ${isMe ? '(Sen)' : ''}`;
        list.appendChild(li);
    });

    if (count) count.textContent = users.length;
}

function initiateHandshake(method) {
    appendSystemMessage(`[!] ${method} El Sıkışması Başlatılıyor...`);
    socket.emit("handshake", {
        method: method,
        step: "INIT"
    });
}

// Dosyanın resim olup olmadığını kontrol eden fonksiyon
function checkIfImage(fileName, fileType = "") {
    if (fileType && fileType.startsWith("image/")) return true;
    const lowerName = fileName.toLowerCase();
    return lowerName.endsWith(".png") || 
           lowerName.endsWith(".jpg") || 
           lowerName.endsWith(".jpeg") || 
           lowerName.endsWith(".gif") || 
           lowerName.endsWith(".webp");
}

// =================== MESAJLAŞMA & DOSYA GÖNDERİMİ ===================

function sendMessage() {
    const messageInput = document.getElementById("message-input");
    const text = messageInput.value.trim();
    if (!text) return;

    const mode = document.getElementById("mode-select")?.value || "GUVENLI";
    const keyMethod = document.getElementById("key-select")?.value || currentHandshake.method;

    if (mode === "GUVENSIZ") {
        socket.emit("send_message", {
            mode: "UNENCRYPTED",
            payload: text
        });
        renderMyMessage(text, "Açık Metin");
    } else {
        socket.emit("send_message", {
            mode: "ENCRYPTED",
            payload: { 
                text: text 
            }
        });
        renderMyMessage(text, keyMethod + " + AES-128");
    }

    messageInput.value = "";
}

function handleFileUpload(event) {
    const file = event.target.files[0];
    if (!file) return;

    if (file.size > 5 * 1024 * 1024) {
        alert("Dosya boyutu 5 MB'dan küçük olmalıdır!");
        event.target.value = "";
        return;
    }

    const isImage = checkIfImage(file.name, file.type);
    const reader = new FileReader();

    reader.onload = function(e) {
        const base64Data = e.target.result;
        const filePayload = JSON.stringify({
            is_file: true,
            is_image: isImage,
            file_name: file.name,
            file_data: base64Data
        });

        const mode = document.getElementById("mode-select")?.value || "GUVENLI";
        const keyMethod = document.getElementById("key-select")?.value || currentHandshake.method;

        if (mode === "GUVENSIZ") {
            socket.emit("send_message", {
                mode: "UNENCRYPTED",
                payload: filePayload
            });
            renderMyMedia(file.name, base64Data, isImage, "Açık Dosya");
        } else {
            socket.emit("send_message", {
                mode: "ENCRYPTED",
                payload: { 
                    text: filePayload 
                }
            });
            renderMyMedia(file.name, base64Data, isImage, keyMethod + " + AES-128");
        }
    };

    reader.readAsDataURL(file);
    event.target.value = "";
}

function renderMyMessage(text, tagText) {
    const container = document.getElementById("messages-container");
    if (!container) return;
    const msgDiv = document.createElement("div");
    msgDiv.className = "message-bubble out";

    msgDiv.innerHTML = `
        <span class="msg-sender">Sen</span>
        ${escapeHtml(text)}
        <div class="msg-meta">
            <span class="crypto-tag">${tagText}</span>
            ${getCurrentTime()}
        </div>
    `;
    container.appendChild(msgDiv);
    container.scrollTop = container.scrollHeight;
}

function renderMyMedia(fileName, base64Data, isImage, tagText) {
    const container = document.getElementById("messages-container");
    if (!container) return;
    const msgDiv = document.createElement("div");
    msgDiv.className = "message-bubble out";

    let mediaHtml = "";
    if (isImage) {
        mediaHtml = `
            <div style="margin: 6px 0;">
                <img src="${base64Data}" alt="${escapeHtml(fileName)}" style="max-width: 240px; max-height: 220px; border-radius: 8px; display: block; object-fit: contain; background: rgba(0,0,0,0.2); cursor: pointer;" onclick="window.open('${base64Data}')">
                <a href="${base64Data}" download="${escapeHtml(fileName)}" style="display: inline-block; font-size: 11px; color: #93c5fd; margin-top: 4px; text-decoration: underline;">
                    <i class="fa-solid fa-download"></i> İndir (${escapeHtml(fileName)})
                </a>
            </div>
        `;
    } else {
        mediaHtml = `
            <div style="display:flex; align-items:center; gap:8px; margin: 4px 0;">
                <i class="fa-solid fa-file-pdf" style="font-size: 26px; color: #ef4444;"></i>
                <a href="${base64Data}" download="${escapeHtml(fileName)}" style="color: #60a5fa; text-decoration: underline; font-weight: 500;">${escapeHtml(fileName)}</a>
            </div>
        `;
    }

    msgDiv.innerHTML = `
        <span class="msg-sender">Sen</span>
        ${mediaHtml}
        <div class="msg-meta">
            <span class="crypto-tag">${tagText}</span>
            ${getCurrentTime()}
        </div>
    `;
    container.appendChild(msgDiv);
    container.scrollTop = container.scrollHeight;
}

function renderIncomingMessage(data) {
    const container = document.getElementById("messages-container");
    if (!container) return;
    const msgDiv = document.createElement("div");
    msgDiv.className = "message-bubble in";

    const isEncrypted = data.mode === "ENCRYPTED";
    let displayText = data.text;

    // Şifreli gelen metni çözme denemesi
    if (isEncrypted && data.ciphertext) {
        try {
            const bytes = CryptoJS.AES.decrypt(data.ciphertext, clientSession.aes_key);
            const decrypted = bytes.toString(CryptoJS.enc.Utf8);
            if (decrypted && decrypted.trim() !== "") {
                displayText = decrypted;
            }
        } catch (e) {
            console.warn("Deşifre denemesi:", e);
        }
    }

    let fileInfo = null;
    try {
        const parsed = JSON.parse(displayText);
        if (parsed && parsed.is_file) {
            fileInfo = parsed;
            if (fileInfo.is_image === undefined) {
                fileInfo.is_image = checkIfImage(fileInfo.file_name);
            }
        }
    } catch (_) {}

    const tagText = isEncrypted ? `AES-128 (${data.cipher_preview || 'Şifreli'})` : "Açık Metin";

    if (fileInfo) {
        let mediaHtml = "";
        const isImg = fileInfo.is_image || checkIfImage(fileInfo.file_name);

        if (isImg) {
            mediaHtml = `
                <div style="margin: 6px 0;">
                    <img src="${fileInfo.file_data}" alt="${escapeHtml(fileInfo.file_name)}" style="max-width: 240px; max-height: 220px; border-radius: 8px; display: block; object-fit: contain; background: rgba(0,0,0,0.2); cursor: pointer;" onclick="window.open('${fileInfo.file_data}')">
                    <a href="${fileInfo.file_data}" download="${escapeHtml(fileInfo.file_name)}" style="display: inline-block; font-size: 11px; color: #93c5fd; margin-top: 4px; text-decoration: underline;">
                        <i class="fa-solid fa-download"></i> İndir (${escapeHtml(fileInfo.file_name)})
                    </a>
                </div>
            `;
        } else {
            mediaHtml = `
                <div style="display:flex; align-items:center; gap:8px; margin: 4px 0;">
                    <i class="fa-solid fa-file-pdf" style="font-size: 26px; color: #ef4444;"></i>
                    <a href="${fileInfo.file_data}" download="${escapeHtml(fileInfo.file_name)}" style="color: #60a5fa; text-decoration: underline; font-weight: 500;">${escapeHtml(fileInfo.file_name)}</a>
                </div>
            `;
        }

        msgDiv.innerHTML = `
            <span class="msg-sender">${escapeHtml(data.sender || data.server || 'Bilinmeyen')}</span>
            ${mediaHtml}
            <div class="msg-meta">
                <span class="crypto-tag">${tagText}</span>
                ${getCurrentTime()}
            </div>
        `;
    } else {
        msgDiv.innerHTML = `
            <span class="msg-sender">${escapeHtml(data.sender || data.server || 'Bilinmeyen')}</span>
            ${escapeHtml(displayText)}
            <div class="msg-meta">
                <span class="crypto-tag">${tagText}</span>
                ${getCurrentTime()}
            </div>
        `;
    }

    container.appendChild(msgDiv);
    container.scrollTop = container.scrollHeight;
}

// =================== YARDIMCI VE ARAYÜZ FONKSİYONLARI ===================

function appendSystemMessage(text) {
    const container = document.getElementById("messages-container");
    if (!container) return;
    const sysDiv = document.createElement("div");
    sysDiv.className = "system-message";
    sysDiv.innerHTML = `<span>${escapeHtml(text)}</span>`;
    container.appendChild(sysDiv);
    container.scrollTop = container.scrollHeight;
}

function getCurrentTime() {
    const now = new Date();
    return now.getHours().toString().padStart(2, '0') + ':' + now.getMinutes().toString().padStart(2, '0');
}

function openProfileModal() {
    const m = document.getElementById("profile-modal");
    if (m) m.style.display = "flex";
}

function closeProfileModal() {
    const m = document.getElementById("profile-modal");
    if (m) m.style.display = "none";
}

function saveProfileSettings() {
    const defaultKey = document.getElementById("profile-default-key")?.value || "KYBER";
    const keySelect = document.getElementById("key-select");
    if (keySelect) keySelect.value = defaultKey;
    closeProfileModal();
    initiateHandshake(defaultKey);
}

function clearChatHistory() {
    const container = document.getElementById("messages-container");
    if (container) {
        container.innerHTML = `<div class="system-message"><span>Sohbet geçmişi temizlendi.</span></div>`;
    }
}

function filterMessages() {
    const query = document.getElementById("chat-search-input")?.value.toLowerCase() || "";
    const bubbles = document.querySelectorAll(".message-bubble");
    bubbles.forEach(bubble => {
        if (bubble.textContent.toLowerCase().includes(query)) {
            bubble.classList.remove("hidden-search");
        } else {
            bubble.classList.add("hidden-search");
        }
    });
}

function escapeHtml(text) {
    if (!text) return "";
    return String(text)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}