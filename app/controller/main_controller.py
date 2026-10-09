"""
from flask import render_template,Blueprint


main_bp = Blueprint('main',__name__)

@main_bp.route('/')
def index():
    return render_template("index.html")
    """

from flask import render_template, Blueprint, request
from flask_socketio import emit
from app import socketio
from app.services.crypto_service import CryptoService
import time
import os

main_bp = Blueprint('main', __name__)

clients = {}

@main_bp.route('/')
def index():
    return render_template("index.html")

@socketio.on('connect')
def handle_connect():
    sid = request.sid
    client_id = f"Kullanici_{sid[:4]}"
    # Varsayılan bir oturum AES anahtarı oluştur (el sıkışma anında da güncellenebilir)
    clients[sid] = {
        "id": client_id,
        "aes_key": os.urandom(16),
        "handshake_state": {}
    }
    print(f"[+] Yeni istemci bağlandı: {client_id} (SID: {sid})")
    emit('connection_response', {'status': 'connected', 'client_id': client_id})

@socketio.on('disconnect')
def handle_disconnect():
    sid = request.sid
    if sid in clients:
        cid = clients[sid]["id"]
        del clients[sid]
        print(f"[-] İstemci ayrıldı: {cid}")

@socketio.on('handshake')
def handle_handshake_event(data):
    sid = request.sid
    method = data.get("method", "KYBER")
    step = data.get("step")
    
    if sid not in clients:
        clients[sid] = {"id": f"Kullanici_{sid[:4]}", "aes_key": os.urandom(16), "handshake_state": {}}
        
    state = clients[sid]["handshake_state"]
    client_id = clients[sid]["id"]

    if step == "INIT":
        state["t_start"] = time.perf_counter()
        state["method"] = method

        if method == "RSA":
            priv, pub_pem, gen_time, pub_size = CryptoService.generate_rsa_keypair()
            state["priv"] = priv
            emit('handshake_response', {
                "method": "RSA", "step": "SERVER_PUB", "pub_key": pub_pem,
                "metrics": {"gen_time_ms": round(gen_time, 2), "pub_size_bytes": pub_size}
            })

        elif method == "ECC":
            priv, pub_pem, gen_time, pub_size = CryptoService.generate_ecc_keypair()
            state["priv"] = priv
            emit('handshake_response', {
                "method": "ECC", "step": "SERVER_PUB", "pub_key": pub_pem,
                "metrics": {"gen_time_ms": round(gen_time, 2), "pub_size_bytes": pub_size}
            })

        elif method == "DH":
            priv, pub_hex, gen_time, pub_size = CryptoService.generate_dh_keypair()
            state["priv"] = priv
            emit('handshake_response', {
                "method": "DH", "step": "SERVER_PUB", "pub_key": pub_hex,
                "metrics": {"gen_time_ms": round(gen_time, 2), "pub_size_bytes": pub_size}
            })

        elif method == "KYBER":
            priv, pub_b64, gen_time, pub_size = CryptoService.generate_kyber_keypair()
            state["priv"] = priv
            emit('handshake_response', {
                "method": "KYBER", "step": "SERVER_PUB", "pub_key": pub_b64,
                "metrics": {"gen_time_ms": round(gen_time, 2), "pub_size_bytes": pub_size}
            })

    elif step == "FINALIZE":
        # Yeni oturum anahtarı türet
        clients[sid]["aes_key"] = os.urandom(16)
        handshake_time = (time.perf_counter() - state.get("t_start", time.perf_counter())) * 1000
        print(f"[✓] [{client_id}] {method} El Sıkışması Bitti: {handshake_time:.2f} ms")

        emit('handshake_response', {
            "step": "OK",
            "method": method,
            "metrics": {"handshake_time_ms": round(handshake_time, 2), "incoming_bytes": 128}
        })

@socketio.on('send_message')
def handle_message(data):
    sid = request.sid
    client_info = clients.get(sid, {"id": "Anonim", "aes_key": os.urandom(16)})
    sender_id = client_info["id"]
    mode = data.get("mode")
    raw_payload = data.get("payload")

    print("\n" + "="*45)
    print(f"[MESAJ GELDİ] Gönderen: {sender_id} | Mod: {mode}")

    # 1. GÜVENSİZ (ŞİFRESİZ) İLETİM
    if mode == "UNENCRYPTED":
        plain_text = raw_payload
        print(f"[AÇIK VERİ]: {plain_text}")
        
        # Gönderen hariç diğer tüm kullanıcılara yayınla (broadcast)
        emit('receive_message', {
            "sender": sender_id,
            "mode": "UNENCRYPTED",
            "text": plain_text
        }, broadcast=True, include_self=False)

    # 2. GÜVENLİ (AES-128 RE-ENCRYPTION) İLETİM
    elif mode == "ENCRYPTED":
        plain_text = raw_payload.get("text", "")
        sender_key = client_info["aes_key"]

        # Sunucuda çözme simülasyonu
        decrypted_text = plain_text
        print(f"[SUNUCUDA ÇÖZÜLDÜ]: {decrypted_text}")

        # Odadaki DİĞER KULLANICILARA yolla
        for target_sid, target_data in list(clients.items()):
            if target_sid != sid:
                target_key = target_data["aes_key"]
                re_encrypted_packet = CryptoService.aes_encrypt(target_key, decrypted_text)
                
                socketio.emit('receive_message', {
                    "sender": sender_id,
                    "mode": "ENCRYPTED",
                    "text": decrypted_text,
                    "cipher_preview": re_encrypted_packet["ciphertext"][:20] + "..."
                }, room=target_sid)
                print(f"[+] {target_data['id']} ({target_sid}) için iletildi.")