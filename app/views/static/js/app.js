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

// Sayfa Yüklendiğinde Dinleyicileri Ata
window.addEventListener("DOMContentLoaded", () => {
    const inputMessage = document.getElementById("message-input");
    if (inputMessage) {
        inputMessage.addEventListener("keypress", (e) => {
            if (e.key === "Enter") sendMessage();
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
        appendSystemMessage(`[✓] ${data.method} ve AES-128 Tüneli Kuruldu! Süre: ${data.metrics.handshake_time_ms} ms`);
    }
});

socket.on("receive_message", (data) => {
    renderIncomingMessage(data);
});

// Giriş ve Oda Yönetimi
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

    // Sunucuya odaya katıldığımızı bildir
    socket.emit("join", {
        username: currentUser.username,
        room: currentUser.room
    });

    updateOnlineList();
    initiateHandshake(document.getElementById("key-select").value);
}

function updateOnlineList() {
    const list = document.getElementById("online-users-list");
    list.innerHTML = `<li><i class="fa-solid fa-circle" style="color: #22c55e; font-size: 8px;"></i> ${escapeHtml(currentUser.username)} (Sen)</li>`;
    document.getElementById("user-count").textContent = "1";
}

function initiateHandshake(method) {
    appendSystemMessage(`[!] ${method} El Sıkışması Başlatılıyor...`);
    socket.emit("handshake", {
        method: method,
        step: "INIT"
    });
}

// Mesaj Gönderme ve Listeleme (style.css sınıflarına uygun)
function sendMessage() {
    const messageInput = document.getElementById("message-input");
    const text = messageInput.value.trim();
    if (!text) return;

    const mode = document.getElementById("mode-select").value;
    const keyMethod = document.getElementById("key-select").value;

    if (mode === "GUVENSIZ") {
        socket.emit("send_message", {
            mode: "UNENCRYPTED",
            payload: text
        });
        renderMyMessage(text, "Açık Metin");
    } else {
        socket.emit("send_message", {
            mode: "ENCRYPTED",
            payload: { text: text }
        });
        renderMyMessage(text, `${keyMethod} + AES-128`);
    }

    messageInput.value = "";
}

function renderMyMessage(text, tagText) {
    const container = document.getElementById("messages-container");
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

function renderIncomingMessage(data) {
    const container = document.getElementById("messages-container");
    const msgDiv = document.createElement("div");
    msgDiv.className = "message-bubble in";

    const isEncrypted = data.mode === "ENCRYPTED";
    const tagText = isEncrypted ? `AES-128 (${data.cipher_preview || 'Şifreli'})` : "Açık Metin";

    msgDiv.innerHTML = `
        <span class="msg-sender">${escapeHtml(data.sender)}</span>
        ${escapeHtml(data.text)}
        <div class="msg-meta">
            <span class="crypto-tag">${tagText}</span>
            ${getCurrentTime()}
        </div>
    `;
    container.appendChild(msgDiv);
    container.scrollTop = container.scrollHeight;
}

function appendSystemMessage(text) {
    const container = document.getElementById("messages-container");
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

// Modal ve Arama Fonksiyonları
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