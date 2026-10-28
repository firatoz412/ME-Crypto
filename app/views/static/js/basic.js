//soket bağlantısı, ortak durum, mesajlaşma ve arayüz yardımcıları

const socket = io({
    transports: ['polling', 'websocket']
});

let currentUser = {
    username: "",
    room: "genel",
    sid: ""
};

let currentHandshake = {
    method: "RSA",
    status: "NOT_STARTED"
};

//oturum anahtarı tut.
let clientSession = {
    aes_key_bytes: null
};

//sayfa yüklenince
window.addEventListener("DOMContentLoaded", () => {
    const inputMessage = document.getElementById("message-input");
    if (inputMessage) {
        inputMessage.addEventListener("keypress", (e) => {
            if (e.key === "Enter") sendMessage();//entera bastım mı mesaj gönder
        });
    }

    //dosya seçici
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

    //dosya seçme butonu = paperclipBtn
    const paperclipBtn = document.querySelector(".fa-paperclip")?.parentElement || document.querySelector("i.fa-paperclip");
    if (paperclipBtn) {
        paperclipBtn.style.cursor = "pointer";
        paperclipBtn.onclick = (e) => {
            e.preventDefault();
            fileInput.click();
        };
    }

    //anahtar yöntemi seç,rsa,dh,ecc,kyber 
    const keySelect = document.getElementById("key-select");
    if (keySelect) {
        keySelect.addEventListener("change", (e) => {
            initiateHandshake(e.target.value);
        });
    }

    //mesaj gönderme moduun seç güvenli ya da güvensiz mod
    const modeSelect = document.getElementById("mode-select");
    if (modeSelect) {
        modeSelect.addEventListener("change", (e) => {
            if (e.target.value === "GUVENLI") {
                const currentKey = document.getElementById("key-select")?.value || "RSA";
                initiateHandshake(currentKey);
            }
        });
    }
});

//socket eventları
socket.on("connect", () => {
    //bağlantı durumu
    const status = document.getElementById("connection-status");
    if (status) {
        status.textContent = "Bağlandı (Çevrimiçi)";
        status.style.color = "#22c55e";
    }
});
//bağlantı durumu
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

//kullanıcı listesini güncelle
socket.on("room_users", (users) => {
    updateOnlineList(users);
});

//gelen mesajı(data) mesajlaşma bölümüne yaz
socket.on("receive_message", (data) => {
    renderIncomingMessage(data);
});

//sistem mesajı yazdırma
socket.on("system_error", (data) => {
    appendSystemMessage(`[X] ${data.message}`);
});


//kulanıcı listesini güncelle
function updateOnlineList(users) {
    const list = document.getElementById("online-users-list");
    const count = document.getElementById("user-count");//user sayısı
    if (!list) return;

    if (!Array.isArray(users) || users.length === 0) {
        users = [currentUser.username || "Siz"];
    }

    //sol panele kulanıcıları yazdır.
    list.innerHTML = "";
    users.forEach(u => {
        const isMe = u === currentUser.username;
        const li = document.createElement("li");
        li.innerHTML = `<i class="fa-solid fa-circle" style="color: #22c55e; font-size: 8px;"></i> ${escapeHtml(u)} ${isMe ? '(Sen)' : ''}`;
        list.appendChild(li);
    });

    if (count) count.textContent = users.length;
}

//Mesajı modunu ayarla
// Mesajı modunu ayarla
async function transmit(text, plainTag) {
    const mode = document.getElementById("mode-select")?.value || "GUVENLI";
    const keyMethod = document.getElementById("key-select")?.value || currentHandshake.method;

    console.log("[DEBUG transmit] Seçilen Mod:", mode);
    console.log("[DEBUG transmit] Seçilen Anahtar Yöntemi:", keyMethod);
    console.log("[DEBUG transmit] clientSession durumu:", clientSession);

    if (mode === "GUVENSIZ") {
        console.log("[DEBUG transmit] Güvensiz modda mesaj gönderiliyor...");
        socket.emit("send_message", { mode: "UNENCRYPTED", payload: text });
        return plainTag;
    }

    // Güvenli mod kontrolü
    if (!clientSession || !clientSession.aes_key_bytes) {
        console.warn("[DEBUG transmit] HATA: clientSession.aes_key_bytes boş veya tanımlı değil!");
        appendSystemMessage("[!] Güvenli tünel henüz kurulmadı. Anahtar yöntemi seçiniz.");
        return null;
    }

    try {
        console.log("[DEBUG transmit] Mesaj şifreleniyor, AES anahtar uzunluğu:", clientSession.aes_key_bytes.length);
        const ciphertext = await aesEncryptText(text, clientSession.aes_key_bytes);
        socket.emit("send_message", { mode: "ENCRYPTED", payload: { ciphertext } });
        console.log("[DEBUG transmit] Şifreli mesaj başarıyla sunucuya gönderildi.");
        return keyMethod + " + AES-128";
    } catch (error) {
        console.error("[DEBUG transmit] Şifreleme sırasında kritik hata:", error);
        appendSystemMessage("[!] Şifreleme hatası oluştu.");
        return null;
    }
}
async function sendMessage() {
    const messageInput = document.getElementById("message-input");
    const text = messageInput.value.trim();
    if (!text) return;

    const tag = await transmit(text, "Açık Metin");
    if (!tag) return;

    renderMyMessage(text, tag);
    messageInput.value = "";
}


//en fazla 5mb lik dosyaya izin var...
function handleFileUpload(event) {
    const file = event.target.files[0];
    if (!file) return;

    if (file.size > 5 * 1024 * 1024) {
        alert("Dosya boyutu 5 MB'dan küçük olmalıdır.");
        event.target.value = "";
        return;
    }

    const isImage = checkIfImage(file.name, file.type);
    const reader = new FileReader();

    reader.onload = async function (e) {
        const base64Data = e.target.result;
        const filePayload = JSON.stringify({
            is_file: true,
            is_image: isImage,
            file_name: file.name,
            file_data: base64Data
        });

        const tag = await transmit(filePayload, "Açık Dosya");
        if (!tag) return;

        renderMyMedia(file.name, base64Data, isImage, tag);
    };

    reader.readAsDataURL(file);
    event.target.value = "";
}

function checkIfImage(fileName, fileType = "") {
    if (fileType && fileType.startsWith("image/")) return true;
    const lowerName = fileName.toLowerCase();
    return lowerName.endsWith(".png") ||
           lowerName.endsWith(".jpg") ||
           lowerName.endsWith(".jpeg") ||
           lowerName.endsWith(".gif") ||
           lowerName.endsWith(".webp");
}

//mesajı renderla yani ekranda göster, yaz
function renderMyMessage(text, tagText) {
    const container = document.getElementById("messages-container");
    if (!container) return;
    const msgDiv = document.createElement("div");
    msgDiv.className = "message-bubble out";

    msgDiv.innerHTML = `
        <span class="msg-sender">Sen</span>
        ${escapeHtml(text)}
        <div class="msg-meta">
            <span class="crypto-tag">${escapeHtml(tagText)}</span>
            ${getCurrentTime()}
        </div>
    `;
    container.appendChild(msgDiv);
    container.scrollTop = container.scrollHeight;
}

function buildMediaHtml(fileName, dataUrl, isImage) {
    if (isImage) {
        return `
            <div style="margin: 6px 0;">
                <img src="${dataUrl}" alt="${escapeHtml(fileName)}" style="max-width: 240px; max-height: 220px; border-radius: 8px; display: block; object-fit: contain; background: rgba(0,0,0,0.2); cursor: pointer;" onclick="window.open('${dataUrl}')">
                <a href="${dataUrl}" download="${escapeHtml(fileName)}" style="display: inline-block; font-size: 11px; color: #93c5fd; margin-top: 4px; text-decoration: underline;">
                    <i class="fa-solid fa-download"></i> İndir (${escapeHtml(fileName)})
                </a>
            </div>
        `;
    }
    return `
        <div style="display:flex; align-items:center; gap:8px; margin: 4px 0;">
            <i class="fa-solid fa-file-pdf" style="font-size: 26px; color: #ef4444;"></i>
            <a href="${dataUrl}" download="${escapeHtml(fileName)}" style="color: #60a5fa; text-decoration: underline; font-weight: 500;">${escapeHtml(fileName)}</a>
        </div>
    `;
}

//medyayı renderla
function renderMyMedia(fileName, base64Data, isImage, tagText) {
    if (!isSafeDataUrl(base64Data)) return;   // XSS koruması

    const container = document.getElementById("messages-container");
    if (!container) return;
    const msgDiv = document.createElement("div");
    msgDiv.className = "message-bubble out";

    msgDiv.innerHTML = `
        <span class="msg-sender">Sen</span>
        ${buildMediaHtml(fileName, base64Data, isImage)}
        <div class="msg-meta">
            <span class="crypto-tag">${escapeHtml(tagText)}</span>
            ${getCurrentTime()}
        </div>
    `;
    container.appendChild(msgDiv);
    container.scrollTop = container.scrollHeight;
}

//gelen mesajı renderla
async function renderIncomingMessage(data) {
    const container = document.getElementById("messages-container");
    if (!container) return;
    const msgDiv = document.createElement("div");
    msgDiv.className = "message-bubble in";

    const isEncrypted = data.mode === "ENCRYPTED";
    let displayText = data.text;

    //mesaj şifreliyse oturum anahtarıyla çöz
    if (isEncrypted && data.ciphertext) {
        try {
            displayText = await aesDecryptText(data.ciphertext, clientSession.aes_key_bytes);
        } catch (e) {
            console.warn("Çözme hatası:", e);
            displayText = "[Mesaj çözülemedi]";
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

    //xss
    if (fileInfo && !isSafeDataUrl(fileInfo.file_data)) {
        fileInfo = null;
        displayText = "[Geçersiz dosya engellendi]";
    }

    const tagText = isEncrypted ? `AES-128 (${data.cipher_preview || 'Şifreli'})` : "Açık Metin";
    const sender = escapeHtml(data.sender || data.server || 'Bilinmeyen');

    const body = fileInfo
        ? buildMediaHtml(fileInfo.file_name, fileInfo.file_data, fileInfo.is_image || checkIfImage(fileInfo.file_name))
        : escapeHtml(displayText);

    msgDiv.innerHTML = `
        <span class="msg-sender">${sender}</span>
        ${body}
        <div class="msg-meta">
            <span class="crypto-tag">${escapeHtml(tagText)}</span>
            ${getCurrentTime()}
        </div>
    `;

    container.appendChild(msgDiv);
    container.scrollTop = container.scrollHeight;
}

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

// XSS koruması
function escapeHtml(text) {
    if (!text) return "";
    return String(text)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// XSS koruması: sadece resim ve PDF data URL'lerine izin ver
function isSafeDataUrl(url) {
    return typeof url === "string" &&
        /^data:(image\/[a-z0-9.+-]+|application\/pdf);base64,[A-Za-z0-9+/=]+$/i.test(url);
}