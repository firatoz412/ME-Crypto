from app.config.database import getDatabase as vt
from flask import render_template, Blueprint, request,session
from flask_socketio import emit,join_room
from app import socketio
from app.services.crypto_service import CryptoService
import time
import os,base64

main_bp = Blueprint('main', __name__)

clients = {}

@main_bp.route('/')
def index():
    return render_template("index.html")

@socketio.on('connect')
def handle_connect():
    sid = request.sid
    session_username = session.get('username')
    client_id = session_username if session_username else f"Kullanici_{sid[:4]}"
    clients[sid] = {
        "id": client_id,
        "room": session.get('room', 'genel'), # Session'da oda varsa al, yoksa genel
        "aes_key": os.urandom(16),
        "secure":False,
        "handshake_state": {}
    }
    print(f"[+] Yeni istemci bağlandı: {client_id} (SID: {sid})")
    emit('connection_response', {'status': 'connected', 'client_id': client_id})

@socketio.on('disconnect')
def handle_disconnect():
    sid = request.sid
    info = clients.pop(sid, None)
    if not info:
        return

    username = info["id"]
    print(f"[-] İstemci ayrıldı: {username}")

    if username.startswith("Kullanici_"):
        return

    if any(c["id"] == username for c in clients.values()):
        return

    try:
        conn = vt()
        if conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE users SET is_online = 0 WHERE username = %s', (username,))
            conn.commit()
            cursor.close()
            conn.close()
    except Exception as e:
        print(f"Disconnect'te DB güncellenemedi: {e}")



def init_rsa(state):
    priv, pub_key, gen_time, pub_size = CryptoService.generate_rsa_keypair()
    state["priv"] = priv
    return pub_key, gen_time, pub_size


def init_ecc(state):
    priv, pub_key, gen_time, pub_size = CryptoService.generate_ecc_keypair()
    state["priv"] = priv
    return pub_key, gen_time, pub_size


def init_dh(state):
    priv, pub_key, gen_time, pub_size = CryptoService.generate_dh_keypair()
    state["priv"] = priv
    return pub_key, gen_time, pub_size


def init_kyber(state):
    priv, pub_key, gen_time, pub_size = CryptoService.generate_kyber_keypair()
    state["priv"] = priv
    return pub_key, gen_time, pub_size


def finalize_rsa(state, payload):
    encrypted_key = base64.b64decode(payload, validate=True)
    return CryptoService.rsa_decrypt_aes_key(state["priv"], encrypted_key)


def finalize_ecc(state, payload):
    client_pub = CryptoService.load_ecc_public_key(
        base64.b64decode(payload, validate=True)
    )
    return CryptoService.ecc_shared_key(state["priv"], client_pub)


def finalize_dh(state, payload):
    client_pub = CryptoService.load_dh_public_key(payload)
    return CryptoService.dh_shared_key(state["priv"], client_pub)


def finalize_kyber(state, payload):
    ciphertext = base64.b64decode(payload, validate=True)
    return CryptoService.kyber_decapsulate(state["priv"], ciphertext)


HANDSHAKE_METHODS = {
    "RSA": {
        "init": init_rsa,
        "finalize": finalize_rsa,
    },
    "ECC": {
        "init": init_ecc,
        "finalize": finalize_ecc,
    },
    "DH": {
        "init": init_dh,
        "finalize": finalize_dh,
    },
    "KYBER": {
        "init": init_kyber,
        "finalize": finalize_kyber,
    },
}


def emit_handshake_error(method, message):
    emit("handshake_response", {
        "step": "ERROR",
        "method": method,
        "message": message,
    })
   
     
@socketio.on("handshake")
def handle_handshake_event(data):
    if not isinstance(data, dict):
        emit_handshake_error(None, "Geçersiz handshake verisi.")
        return

    sid = request.sid
    requested_method = data.get("method", "RSA")
    step = data.get("step")

    client = clients.setdefault(sid, {
        "id": f"Kullanici_{sid[:4]}",
        "aes_key": os.urandom(16),
        "secure": False,
        "handshake_state": {},
    })

    state = client["handshake_state"]
    client_id = client["id"]

    if step == "INIT":
        method = requested_method#mesajlaşma yöntemi
        handlers = HANDSHAKE_METHODS.get(method)#metot işlemleri için...

        if handlers is None:
            emit_handshake_error(method, f"Desteklenmeyen yöntem: {method}")
            return

        client["secure"] = False
        state.clear()#önceki handshake bilgilerini clearla (seçilen yöntem,anahtarlar vb..)
        state["t_start"] = time.perf_counter()#zamanı tut
        state["method"] = method#metodu yaz

        try:
            pub_key, gen_time, pub_size = handlers["init"](state)
        except Exception as exc:
            state.clear()
            emit_handshake_error(method, str(exc))
            return

        emit("handshake_response", {#emit=iştemciye mesaj gönder
            "method": method,
            "step": "SERVER_PUB",
            "pub_key": pub_key,
            "metrics": {
                "gen_time_ms": round(gen_time, 2),
                "pub_size_bytes": pub_size,
            },
        })
        return

    if step == "FINALIZE":
        method = state.get("method")
        handlers = HANDSHAKE_METHODS.get(method)

        if handlers is None or "priv" not in state:
            emit_handshake_error(method, "Aktif handshake bulunamadı; önce INIT gönderin.")
            return

        payload = data.get("payload")

        try:
            aes_key = handlers["finalize"](state, payload)

            if len(aes_key) != 16:
                raise ValueError("AES anahtarı 16 bayt olmalı.")
        except Exception as exc:
            emit_handshake_error(method, str(exc))
            return

        client["aes_key"] = aes_key
        client["secure"] = True

        handshake_time = (
            time.perf_counter() - state["t_start"]
        ) * 1000

        print(
            f"[✓] [{client_id}] {method} El Sıkışması Bitti: "
            f"{handshake_time:.2f} ms"
        )

        emit("handshake_response", {
            "step": "OK",
            "method": method,
            "metrics": {
                "handshake_time_ms": round(handshake_time, 2),
                "incoming_bytes": len(payload or ""),
            },
        })
        return

    emit_handshake_error(requested_method, f"Geçersiz handshake adımı: {step}")      
        
@socketio.on('send_message')
def handle_message(data):
    sid = request.sid
    client_info = clients.get(sid)
    
    if not client_info:
        print(f"[DEBUG HATA] send_message geldi ama kayıtlı istemci yok! SID: {sid}")
        return
    
    sender_id = client_info["id"]
    room = client_info.get("room", "genel")
    is_secure = client_info.get("secure", False)
    has_aes = client_info.get("aes_key") is not None
    
    mode = data.get("mode")
    raw_payload = data.get("payload")

    print("\n" + "="*50)
    print(f"[AĞDAN MESAJ GELDİ] Gönderen: {sender_id} | Oda: {room} | Mod: {mode}")
    print(f"[DEBUG KONTROL] İstemci Secure Flag: {is_secure} | AES Anahtarı Mevcut mu?: {has_aes}")

    if mode == "UNENCRYPTED":
        print(f"[AÇIK VERİ]: {str(raw_payload)[:80]}")
        socketio.emit('receive_message', {
            "sender": sender_id,
            "mode": "UNENCRYPTED",
            "text": raw_payload
        }, to=room, skip_sid=sid)

    elif mode == "ENCRYPTED":
        if not is_secure or not has_aes:
            print(f"[HATA] İstemci güvenli tünel kurmamış ama şifreli mesaj gönderiyor! SID: {sid}")
            emit('system_error', {"message": "Güvenli tünel kurulmadan şifreli mesaj gönderilemez"}, to=sid)
            return

        try:
            ciphertext_b64 = raw_payload.get("ciphertext")
            print(f"[DEBUG] Alınan Ciphertext (Base64 uzunluğu): {len(ciphertext_b64) if ciphertext_b64 else 'YOK'}")
            
            raw = base64.b64decode(ciphertext_b64)
            t0 = time.perf_counter()
            
            # AES Çözme işlemi
            plain_text = CryptoService.aes_decrypt(client_info["aes_key"], raw).decode("utf-8")
            dec_ms = (time.perf_counter() - t0) * 1000
            
        except Exception as e:
            print(f"[KRİTİK HATA] Sunucu mesajı çözerken patladı: {str(e)}")
            import traceback
            traceback.print_exc()
            emit('system_error', {"message": f"Sunucu tarafında mesaj çözülemedi: {str(e)}"}, to=sid)
            return

        print(f"[SUNUCUDA ÇÖZÜLDÜ (AES-128)] ({dec_ms:.3f} ms): {plain_text[:80]}")

        # Mesajı diğer kullanıcılara iletme
        target_count = 0
        for other_sid, other in clients.items():
            if other_sid == sid or other.get("room") != room:
                continue
            if not other.get("secure") or not other.get("aes_key"):
                print(f"[DEBUG] Hedef client ({other.get('id')}) güvenli değil, atlanıyor.")
                continue
                
            enc = CryptoService.aes_encrypt(other["aes_key"], plain_text)
            socketio.emit('receive_message', {
                "sender": sender_id,
                "mode": "ENCRYPTED",
                "ciphertext": base64.b64encode(enc["raw"]).decode("utf-8"),
                "cipher_preview": enc["ciphertext"][:20] + "..."
            }, to=other_sid)
            target_count += 1
            
        print(f"[✓] Mesaj {target_count} kişiye başarıyla şifrelenip iletildi.")

    print("="*50)
    

@socketio.on('join')
def handle_join(data):
    sid = request.sid
    if sid not in clients:
        return
    
    username = data.get("username")
    room = data.get("room", "genel")
    
    clients[sid]["id"] = username
    clients[sid]["room"] = room
    join_room(room)

    users = [c["id"] for c in clients.values() if c.get("room") == room]
    emit('room_users', users, to=room)
    print(f"[+] {username} '{room}' odasına katıldı")