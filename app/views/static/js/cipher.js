import { createMlKem768 } from "mlkem";

function bytesToB64(bytes) {
    let s = "";
    const chunk = 0x8000;   // büyük dosyalarda "çok fazla argüman" hatasını önler
    for (let i = 0; i < bytes.length; i += chunk) {
        s += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
    }
    return btoa(s);
}

function b64ToBytes(b64) {
    return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

async function aesEncryptText(text, keyBytes) {
    const key = await crypto.subtle.importKey("raw", keyBytes, { name: "AES-CBC" }, false, ["encrypt"]);
    const iv = crypto.getRandomValues(new Uint8Array(16));
    const ct = new Uint8Array(await crypto.subtle.encrypt(
        { name: "AES-CBC", iv }, key, new TextEncoder().encode(text)
    ));
    const out = new Uint8Array(16 + ct.length);
    out.set(iv, 0);
    out.set(ct, 16);
    return bytesToB64(out);
}

async function aesDecryptText(b64, keyBytes) {
    const raw = b64ToBytes(b64);
    const key = await crypto.subtle.importKey("raw", keyBytes, { name: "AES-CBC" }, false, ["decrypt"]);
    const pt = await crypto.subtle.decrypt(
        { name: "AES-CBC", iv: raw.slice(0, 16) }, key, raw.slice(16)
    );
    return new TextDecoder().decode(pt);
}

async function rsaHandshake(pem) {
    const b64 = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
    const der = b64ToBytes(b64);

    const pubKey = await crypto.subtle.importKey(
        "spki", der, { name: "RSA-OAEP", hash: "SHA-1" }, false, ["encrypt"]
    );

    const aesKey = crypto.getRandomValues(new Uint8Array(16));
    const encrypted = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, pubKey, aesKey);

    clientSession.aes_key_bytes = aesKey;   // mesaj şifrelemede kullanılacak
    return bytesToB64(new Uint8Array(encrypted));
}

async function hkdf16(secretBytes) {
    const base = await crypto.subtle.importKey("raw", secretBytes, "HKDF", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits(
        { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: new Uint8Array(0) },
        base, 128
    );
    return new Uint8Array(bits);
}

async function eccHandshake(pem) {
    const der = b64ToBytes(pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""));
    const serverPub = await crypto.subtle.importKey(
        "spki", der, { name: "ECDH", namedCurve: "P-256" }, false, []
    );

    const pair = await crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]
    );
    const shared = new Uint8Array(await crypto.subtle.deriveBits(
        { name: "ECDH", public: serverPub }, pair.privateKey, 256
    ));
    clientSession.aes_key_bytes = await hkdf16(shared);

    const myPub = new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey));
    return bytesToB64(myPub);
}

async function kyberHandshake(pubB64) {
    const pubBytes = b64ToBytes(pubB64);
    const mlkem = await createMlKem768();
    const [ciphertext, sharedSecret] = mlkem.encap(pubBytes);
    clientSession.aes_key_bytes = await hkdf16(sharedSecret);
    return bytesToB64(ciphertext);
}

const DH_P = BigInt("0x" +
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF");
const DH_G = 2n;

function modPow(base, exp, mod) {
    let result = 1n;
    base %= mod;
    while (exp > 0n) {
        if (exp & 1n) result = (result * base) % mod;
        base = (base * base) % mod;
        exp >>= 1n;
    }
    return result;
}

function bigToBytes(n, length) {
    const hex = n.toString(16).padStart(length * 2, "0");
    return Uint8Array.from(hex.match(/../g).map(h => parseInt(h, 16)));
}

async function dhHandshake(serverPubHex) {
    const y = BigInt("0x" + serverPubHex);
    if (!(y > 1n && y < DH_P - 1n)) throw new Error("Geçersiz DH açık değeri");

    const privBytes = crypto.getRandomValues(new Uint8Array(32));   // 256 bit, sunucuyla aynı
    const a = BigInt("0x" + Array.from(privBytes, b => b.toString(16).padStart(2, "0")).join(""));

    const myPub = modPow(DH_G, a, DH_P);
    const shared = modPow(y, a, DH_P);

    // Sunucu: shared.to_bytes(256, 'big') -> HKDF
    clientSession.aes_key_bytes = await hkdf16(bigToBytes(shared, 256));
    return myPub.toString(16);   // sunucu int(hex, 16) ile okur
}

function initiateHandshake(method) {
    clientSession.aes_key_bytes = null;   // eski anahtar, yeni el sıkışma bitene kadar geçersiz
    currentHandshake.status = "NOT_STARTED";
    appendSystemMessage(`[!] ${method} El Sıkışması Başlatılıyor...`);
    socket.emit("handshake", {
        method: method,
        step: "INIT"
    });
}

socket.on("handshake_response", async (data) => {
    if (data.step === "SERVER_PUB") {
        appendSystemMessage(`[${data.method}] Sunucu açık anahtarı alındı (${data.metrics.pub_size_bytes} byte). El sıkışma tamamlanıyor...`);

        let payload;
        try {
            if (data.method === "RSA") {
                payload = await rsaHandshake(data.pub_key);
            } else if (data.method === "ECC") {
                payload = await eccHandshake(data.pub_key);
            } else if (data.method === "DH") {
                payload = await dhHandshake(data.pub_key);
            } else if(data.method == "KYBER"){
                payload = await kyberHandshake(data.pub_key)
            }else {
                appendSystemMessage(`[!] ${data.method} henüz entegre edilmedi.`);
                return;
            }
        } catch (e) {
            clientSession.aes_key_bytes = null;
            appendSystemMessage(`[X] ${data.method} istemci hatası: ${e.message}`);
            return;
        }
        socket.emit("handshake", { method: data.method, step: "FINALIZE", payload });

    } else if (data.step === "OK") {
        currentHandshake.status = "SECURE";
        currentHandshake.method = data.method;
        appendSystemMessage(`[✓] ${data.method} ve AES-128 tüneli kuruldu! Süre: ${data.metrics.handshake_time_ms} ms`);

    } else if (data.step === "ERROR") {
        clientSession.aes_key_bytes = null;
        appendSystemMessage(`[X] El sıkışma hatası: ${data.message}`);
    }
});


window.initiateHandshake = initiateHandshake;
window.aesEncryptText = aesEncryptText;
window.aesDecryptText = aesDecryptText;