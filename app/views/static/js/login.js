let currentAuthMode = "login";

window.addEventListener("DOMContentLoaded", () => {
    const passwordInput = document.getElementById("password-input");
    if (passwordInput) {
        passwordInput.addEventListener("keypress", (e) => {
            if (e.key === "Enter") handleAuthSubmit();
        });
    }

    checkSession();
});

//oturumu kontrol etme sayfa yenilenmesine karşı
function checkSession() {
    fetch("/api/check-session")
        .then(r => r.json())
        .then(data => {
            if (!data.logged_in) return;

            currentUser.username = data.username;
            currentUser.room = data.room;

            const displayUser = document.getElementById("display-username");
            if (displayUser) displayUser.textContent = data.username;

            const avatar = document.getElementById("my-avatar");
            if (avatar) avatar.textContent = data.username.charAt(0).toUpperCase();

            const modal = document.getElementById("login-modal");
            if (modal) modal.style.display = "none";

            socket.emit("join", { username: data.username, room: data.room });
            initiateHandshake(document.getElementById("key-select")?.value || "RSA");
        })
        .catch(() => {});
}

function switchAuthTab(mode) {
    currentAuthMode = mode;
    clearAuthMessages();

    const loginTab = document.getElementById("tab-login-btn");
    const registerTab = document.getElementById("tab-register-btn");
    const mainBtn = document.getElementById("auth-main-btn");

    const setActive = (tab, active) => {
        if (!tab) return;
        tab.style.color = active ? "#38bdf8" : "#94a3b8";
        tab.style.borderBottom = active ? "2px solid #38bdf8" : "2px solid transparent";
    };

    setActive(loginTab, mode === "login");
    setActive(registerTab, mode !== "login");
    if (mainBtn) mainBtn.textContent = mode === "login" ? "Giriş Yap" : "Kayıt Ol ve Giriş Yap";
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
            body: JSON.stringify({
                username,
                password,
                room: roomSelect ? roomSelect.value : "genel"
            })
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

            const modal = document.getElementById("login-modal");
            if (modal) modal.style.display = "none";

            updateOnlineList([currentUser.username]);

            socket.once("connect", () => {
                socket.emit("join", {
                    username: currentUser.username,
                    room: currentUser.room
                });
                const keySel = document.getElementById("key-select");
                initiateHandshake(keySel ? keySel.value : "RSA");
            });
            socket.disconnect();
            socket.connect();
        } else {
            showAuthMessage(data.message || "Giriş başarısız!", "error");
        }
    } catch (err) {
        showAuthMessage("Sunucuya bağlanılamadı!", "error");
    }
}

//kayıt ol ve giriş yap
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
            setTimeout(() => handleLogin(), 600);
        } else {
            showAuthMessage(data.message || "Kayıt başarısız!", "error");
        }
    } catch (err) {
        showAuthMessage("Sunucuya bağlanılamadı!", "error");
    }
}

async function logoutUser() {
    try {
        const response = await fetch('/api/logout', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });
        const data = await response.json();

        if (data.success) {
            window.location.reload();
        } else {
            alert("Çıkış yapılırken bir sorun oluştu.");
        }
    } catch (error) {
        console.error("Çıkış isteği başarısız:", error);
        window.location.reload();
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