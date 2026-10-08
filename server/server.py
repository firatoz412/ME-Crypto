import socket
import threading
import json
import base64
import os
import time
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parent))
from crypto_engine import CryptoEngine

HOST = '0.0.0.0'
PORT = 5000

engine = CryptoEngine()
clients = {}  # { conn: {"id": "Client_X", "aes_key": b'...', "handshake_state": {}} }
client_lock = threading.Lock()

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "received_files")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def forward_packet(sender_conn, target_packet_bytes):
    with client_lock:
        for conn in clients:
            if conn != sender_conn:
                try:
                    conn.sendall(target_packet_bytes + b"\n")
                except Exception as e:
                    print(f"[-] Yönlendirme hatası: {e}")

def handle_handshake(conn, packet):
    """Hocanın istediği 4 anahtar yönteminin sunucu tarafı ve ölçümleri"""
    method = packet.get("method")
    step = packet.get("step")
    state = clients[conn]["handshake_state"]
    client_id = clients[conn]["id"]

    if step == "INIT":
        state["t_start"] = time.perf_counter()
        if method == "RSA":
            priv, pub_pem, gen_time, pub_size = engine.generate_rsa_keypair()
            state["priv"] = priv
            response = {"type": "HANDSHAKE", "method": "RSA", "step": "SERVER_PUB", "pub_key": pub_pem}
            print(f"[*] [{client_id}] RSA Anahtar Üretildi: {gen_time:.2f} ms | Gönderilen Paket: {pub_size} byte")
            conn.sendall((json.dumps(response) + "\n").encode('utf-8'))

        elif method == "KYBER":
            priv, pub_b64, gen_time, pub_size = engine.generate_kyber_keypair()
            state["priv"] = priv
            response = {"type": "HANDSHAKE", "method": "KYBER", "step": "SERVER_PUB", "pub_key": pub_b64}
            print(f"[*] [{client_id}] Kyber-768 Anahtar Üretildi: {gen_time:.2f} ms | Gönderilen Paket: {pub_size} byte")
            conn.sendall((json.dumps(response) + "\n").encode('utf-8'))

    elif step == "FINALIZE":
        if method == "KYBER":
            import pqcrypto.kem.ml_kem_768 as kyber768
            ciphertext = base64.b64decode(packet["ciphertext"])
            shared_secret = kyber768.decaps(state["priv"], ciphertext)
            clients[conn]["aes_key"] = shared_secret[:16]
            handshake_time = (time.perf_counter() - state["t_start"]) * 1000
            print(f"[✓] [{client_id}] KYBER El Sıkışması Tamam! Süre: {handshake_time:.2f} ms | Gelen Paket: {len(ciphertext)} byte")
            conn.sendall((json.dumps({"type": "HANDSHAKE_OK"}) + "\n").encode('utf-8'))

def handle_client(conn, addr):
    client_id = f"Client_{addr[1]}"
    with client_lock:
        clients[conn] = {"id": client_id, "aes_key": None, "handshake_state": {}}
    print(f"[+] Yeni istemci bağlandı: {client_id} ({addr})")

    buffer = ""
    try:
        while True:
            data = conn.recv(8192).decode('utf-8', errors='ignore')
            if not data:
                break
            buffer += data
            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                if not line.strip(): continue

                packet = json.loads(line.strip())
                msg_type = packet.get("type")
                mode = packet.get("mode")

                if msg_type == "HANDSHAKE":
                    handle_handshake(conn, packet)
                    continue

                print("\n" + "="*45)
                print(f"[PAKET GELDİ] Gönderen: {client_id} | Mod: {mode}")

                # 1. GÜVENSİZ MOD
                if mode == "UNENCRYPTED":
                    print(f"[AÇIK VERİ]: {packet.get('payload')}")
                    forward_packet(conn, line.strip().encode('utf-8'))

                # 2. GÜVENLİ MOD (AES-128 Çöz -> Ekrana Yaz -> Yeniden Şifrele -> İlet)
                elif mode == "ENCRYPTED":
                    sender_key = clients[conn]["aes_key"]
                    if not sender_key:
                        print("[-] Hata: Güvenli modda veri geldi ama henüz AES anahtarı yok!")
                        continue

                    # Çözme işlemi
                    decrypted_text = engine.decrypt_aes(sender_key, packet["payload"])
                    print(f"[GÜVENLİ İÇERİK ÇÖZÜLDÜ]: {decrypted_text}")

                    # Diğer istemciye yönlendirmek için onun anahtarıyla tekrar şifreleme
                    with client_lock:
                        other_clients = [c for c in clients if c != conn]
                        for oc in other_clients:
                            target_key = clients[oc]["aes_key"]
                            if target_key:
                                re_encrypted_payload = engine.encrypt_aes(target_key, decrypted_text)
                                out_packet = {
                                    "type": msg_type,
                                    "mode": "ENCRYPTED",
                                    "sender": client_id,
                                    "payload": re_encrypted_payload
                                }
                                oc.sendall((json.dumps(out_packet) + "\n").encode('utf-8'))
                                print(f"[+] Veri {clients[oc]['id']} için yeniden şifrelenip iletildi.")
                print("="*45)

    except Exception as e:
        print(f"[-] İstemci hatası: {e}")
    finally:
        with client_lock:
            if conn in clients: del clients[conn]
        conn.close()
        print(f"[-] İstemci ayrıldı: {client_id}")

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(2)
    print(f"[*] Gelişmiş Hibrit Kripto Sunucu Dinlemede: {HOST}:{PORT}")
    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    start_server()