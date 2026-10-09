// Sunucunun IP'sine doğrudan bağlan
const socket = io(window.location.origin, {
    transports: ['websocket', 'polling']
});

// Durum Yönetimi
let currentUser = {
    username: "",
    room: "genel",
    sid: ""
};

let currentHandshake = {
    method: "KYBER",
    status: "NOT_STARTED"
};

// SAYFA YÜKLENİNCE 
window.addEventListener("DOMContentLoaded", () => {
    const inputMessage = document.getElementById("message-input");
    if (inputMessage) {
        inputMessage.addEventListener("keypress", (e) => {
            if (e.key === "Enter") {
                sendMessage();
            }
        });
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
                initiateHandshake(document.getElementById("key-select").value);
            }
        });
    }
});

// SOCKET EVENT DİNLEYİCİLERİ 
socket.on("connect", () => {
    document.getElementById("connection-status").textContent = "Bağlandı (Çevrimiçi)";
    document.getElementById("connection-status").style.color = "#10b981";
});

socket.on("disconnect", () => {
    document.getElementById("connection-status").textContent = "Bağlantı Kesildi";
    document.getElementById("connection-status").style.color = "#ef4444";
});

socket.on("connection_response", (data) => {
    currentUser.sid = data.client_id;
    const profileSid = document.getElementById("profile-session-id");
    if (profileSid) profileSid.value = data.client_id;
});

// Sunucudan gelen el sıkışma yanıtı
socket.on("handshake_response", (data) => {
    if (data.step === "SERVER_PUB") {
        appendSystemMessage(`[${data.method}] Sunucu Açık Anahtarı Alındı (${data.metrics.pub_size_bytes} byte). El sıkışma tamamlanıyor...`);
        
        // Client adımını finalize isteği ile sunucuya yolla
        socket.emit("handshake", {
            method: data.method,
            step: "FINALIZE",
            payload: "CLIENT_HANDSHAKE_READY"
        });
    } else if (data.step === "OK") {
        currentHandshake.status = "SECURE";
        currentHandshake.method = data.method;
        appendSystemMessage(`[✓] ${data.method} ve AES-128 Tüneli Kuruldu! Süre: ${data.metrics.handshake_time_ms} ms`);
    }
});

// Gelen mesajları karşıla
socket.on("receive_message", (data) => {
    renderIncomingMessage(data);
});

// GİRİŞ & ODA YÖNETİMİ 
function joinChat() {
    const usernameInput = document.getElementById("username-input");
    const roomSelect = document.getElementById("room-select");

    const username = usernameInput.value.trim();
    if (!username) {
        alert("Lütfen bir kullanıcı adı girin!");
        return;
    }

    currentUser.username = username;
    currentUser.room = roomSelect.value;

    document.getElementById("display-username").textContent = username;
    document.getElementById("my-avatar").textContent = username.charAt(0).toUpperCase();
    document.getElementById("current-room-badge").textContent = roomSelect.options[roomSelect.selectedIndex].text;
    document.getElementById("profile-username-input").value = username;

    document.getElementById("login-modal").style.display = "none";
    updateOnlineList();

    // Girişte varsayılan güvenli el sıkışmayı başlat
    const selectedKey = document.getElementById("key-select").value;
    initiateHandshake(selectedKey);
}

function updateOnlineList() {
    const list = document.getElementById("online-users-list");
    list.innerHTML = `<li><i class="fa-solid fa-circle" style="color: #10b981; font-size: 8px;"></i> ${currentUser.username} (Sen)</li>`;
    document.getElementById("user-count").textContent = "1";
}

//  EL SIKIŞMA (HANDSHAKE)
function initiateHandshake(method) {
    appendSystemMessage(`[!] ${method} El Sıkışması Başlatılıyor...`);
    socket.emit("handshake", {
        method: method,
        step: "INIT"
    });
}

//  MESAJ GÖNDERME & LİSTELEME 
function sendMessage() {
    const messageInput = document.getElementById("message-input");
    const text = messageInput.value.trim();
    if (!text) return;

    const mode = document.getElementById("mode-select").value; // 'GUVENLI' veya 'GUVENSIZ'
    const keyMethod = document.getElementById("key-select").value;

    if (mode === "GUVENSIZ") {
        socket.emit("send_message", {
            mode: "UNENCRYPTED",
            payload: text
        });
        renderMyMessage(text, "Açık Metin (Şifresiz)", "#6b7280");
    } else {
        socket.emit("send_message", {
            mode: "ENCRYPTED",
            payload: {
                text: text
            }
        });
        renderMyMessage(text, `${keyMethod} + AES-128`, "#10b981");
    }

    messageInput.value = "";
}
function renderMyMessage(text, metaText, badgeColor) {
    const container = document.getElementById("messages-container");
    const msgDiv = document.createElement("div");
    msgDiv.style.margin = "8px 0";
    msgDiv.style.display = "flex";
    msgDiv.style.flexDirection = "column";
    msgDiv.style.alignItems = "flex-end";

    msgDiv.innerHTML = `
        <div style="background: #2563eb; color: #fff; padding: 10px 14px; border-radius: 12px 12px 2px 12px; max-width: 70%; word-break: break-word;">
            ${escapeHtml(text)}
        </div>
        <small style="color: ${badgeColor}; font-size: 11px; margin-top: 3px;">
            <i class="fa-solid fa-lock"></i> ${metaText} • Sen
        </small>
    `;
    container.appendChild(msgDiv);
    container.scrollTop = container.scrollHeight;
}

function renderIncomingMessage(data) {
    const container = document.getElementById("messages-container");
    const msgDiv = document.createElement("div");
    msgDiv.style.margin = "8px 0";
    msgDiv.style.display = "flex";
    msgDiv.style.flexDirection = "column";
    msgDiv.style.alignItems = "flex-start";

    const isEncrypted = data.mode === "ENCRYPTED";
    const badgeText = isEncrypted ? `AES-128 Çözüldü (Re-encrypted: ${data.cipher_preview})` : "Açık Metin (Güvensiz)";
    const badgeColor = isEncrypted ? "#10b981" : "#ef4444";

    msgDiv.innerHTML = `
        <div style="background: #1e293b; color: #f8fafc; padding: 10px 14px; border-radius: 12px 12px 12px 2px; max-width: 70%; word-break: break-word; border: 1px solid #334155;">
            ${escapeHtml(data.text)}
        </div>
        <small style="color: ${badgeColor}; font-size: 11px; margin-top: 3px;">
            <i class="fa-solid fa-shield"></i> ${badgeText} • ${data.sender}
        </small>
    `;
    container.appendChild(msgDiv);
    container.scrollTop = container.scrollHeight;
}

function appendSystemMessage(text) {
    const container = document.getElementById("messages-container");
    const sysDiv = document.createElement("div");
    sysDiv.className = "system-message";
    sysDiv.style.textAlign = "center";
    sysDiv.style.margin = "8px 0";
    sysDiv.innerHTML = `<span style="background: #334155; color: #94a3b8; font-size: 12px; padding: 4px 10px; border-radius: 6px;">${escapeHtml(text)}</span>`;
    container.appendChild(sysDiv);
    container.scrollTop = container.scrollHeight;
}

//  MODAL & DİĞER FONKSİYONLAR
function openProfileModal() {
    document.getElementById("profile-modal").style.display = "flex";
}

function closeProfileModal() {
    document.getElementById("profile-modal").style.display = "none";
}

function saveProfileSettings() {
    const defaultKey = document.getElementById("profile-default-key").value;
    document.getElementById("key-select").value = defaultKey;
    closeProfileModal();
    initiateHandshake(defaultKey);
}

function clearChatHistory() {
    const container = document.getElementById("messages-container");
    container.innerHTML = `<div class="system-message"><span>Sohbet geçmişi temizlendi.</span></div>`;
}

function filterMessages() {
    const query = document.getElementById("chat-search-input").value.toLowerCase();
    const messages = document.querySelectorAll("#messages-container > div");
    messages.forEach(msg => {
        if (msg.textContent.toLowerCase().includes(query)) {
            msg.style.display = "";
        } else {
            msg.style.display = "none";
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