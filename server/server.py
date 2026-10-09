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
import pqcrypto.kem.ml_kem_768 as kyber768

HOST = '0.0.0.0'
PORT = 5000

engine = CryptoEngine()
clients = {}
client_lock = threading.Lock()

def forward_packet(sender_conn, target_packet_bytes):
    with client_lock:
        for conn in clients:
            if conn != sender_conn:
                try:
                    conn.sendall(target_packet_bytes + b"\n")
                except Exception as e:
                    print(f"[-] Yönlendirme hatası: {e}")

def handle_handshake(conn, packet):
    method = packet.get("method")
    step = packet.get("step")
    state = clients[conn]["handshake_state"]
    client_id = clients[conn]["id"]

    # INIT (Sunucu Açık Anahtarlarını Üretir ve Yollar) 
    if step == "INIT":
        state["t_start"] = time.perf_counter()
        state["method"] = method

        if method == "RSA":
            priv, pub_pem, gen_time, pub_size = engine.generate_rsa_keypair()
            state["priv"] = priv
            resp = {"type": "HANDSHAKE", "method": "RSA", "step": "SERVER_PUB", "pub_key": pub_pem}
            print(f"[*] [{client_id}] RSA-2048 Üretildi: {gen_time:.2f} ms | Gönderilen: {pub_size} byte")
            conn.sendall((json.dumps(resp) + "\n").encode('utf-8'))

        elif method == "ECC":
            priv, pub_pem, gen_time, pub_size = engine.generate_ecc_keypair()
            state["priv"] = priv
            resp = {"type": "HANDSHAKE", "method": "ECC", "step": "SERVER_PUB", "pub_key": pub_pem}
            print(f"[*] [{client_id}] ECC SECP256R1 Üretildi: {gen_time:.2f} ms | Gönderilen: {pub_size} byte")
            conn.sendall((json.dumps(resp) + "\n").encode('utf-8'))

        elif method == "DH":
            priv, pub_pem, param_pem, gen_time, pub_size = engine.generate_dh_keypair()
            state["priv"] = priv
            resp = {
                "type": "HANDSHAKE",
                "method": "DH",
                "step": "SERVER_PUB",
                "pub_key": pub_pem,
                "dh_params": param_pem
            }
            print(f"[*] [{client_id}] DH-2048 Üretildi: {gen_time:.2f} ms | Gönderilen: {pub_size} byte")
            conn.sendall((json.dumps(resp) + "\n").encode('utf-8'))

        elif method == "KYBER":
            priv, pub_b64, gen_time, pub_size = engine.generate_kyber_keypair()
            state["priv"] = priv
            resp = {"type": "HANDSHAKE", "method": "KYBER", "step": "SERVER_PUB", "pub_key": pub_b64}
            print(f"[*] [{client_id}] Kyber-768 Üretildi: {gen_time:.2f} ms | Gönderilen: {pub_size} byte")
            conn.sendall((json.dumps(resp) + "\n").encode('utf-8'))

    # FINALIZE (İstemciden Gelenle Ortak Anahtarı Çözer)
    elif step == "FINALIZE":
        raw_payload = packet.get("payload")
        incoming_bytes_len = len(str(raw_payload).encode('utf-8'))

        if method == "RSA":
            enc_secret = base64.b64decode(raw_payload)
            shared_secret = engine.decrypt_rsa_secret(state["priv"], enc_secret)
            clients[conn]["aes_key"] = shared_secret[:16]

        elif method == "ECC":
            clients[conn]["aes_key"] = engine.derive_ecc_secret(state["priv"], raw_payload)

        elif method == "DH":
            clients[conn]["aes_key"] = engine.derive_dh_secret(state["priv"], raw_payload)

        elif method == "KYBER":
            ciphertext = base64.b64decode(raw_payload)
            shared_secret = kyber768.decaps(state["priv"], ciphertext)
            clients[conn]["aes_key"] = shared_secret[:16]

        handshake_time = (time.perf_counter() - state["t_start"]) * 1000
        print(f"[✓] [{client_id}] {method} El Sıkışması Bitti! Süre: {handshake_time:.2f} ms | Gelen: {incoming_bytes_len} byte")
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

                if mode == "UNENCRYPTED":
                    print(f"[AÇIK VERİ]: {packet.get('payload')}")
                    forward_packet(conn, line.strip().encode('utf-8'))

                elif mode == "ENCRYPTED":
                    sender_key = clients[conn]["aes_key"]
                    if not sender_key:
                        print("[-] Hata: AES anahtarı yok!")
                        continue

                    decrypted_text = engine.decrypt_aes(sender_key, packet["payload"])
                    print(f"[GÜVENLİ İÇERİK ÇÖZÜLDÜ]: {decrypted_text}")

                    with client_lock:
                        for oc in [c for c in clients if c != conn]:
                            target_key = clients[oc]["aes_key"]
                            if target_key:
                                re_enc = engine.encrypt_aes(target_key, decrypted_text)
                                out = {
                                    "type": msg_type,
                                    "mode": "ENCRYPTED",
                                    "sender": client_id,
                                    "payload": re_enc
                                }
                                oc.sendall((json.dumps(out) + "\n").encode('utf-8'))
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
    server.listen(5)
    print(f"[*] Hibrit Kripto Sunucu Dinlemede: {HOST}:{PORT}")
    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    start_server()