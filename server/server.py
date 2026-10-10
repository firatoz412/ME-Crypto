import socket
import threading
import json
import time
import sys
from pathlib import Path

# Arkadaşının CryptoService sınıfını bağla
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(PROJECT_ROOT))
from app.services.crypto_service import CryptoService

HOST = '0.0.0.0'
PORT = 5000

clients = {}
client_lock = threading.Lock()

def forward_packet(sender_conn, data_bytes):
    with client_lock:
        for conn in clients:
            if conn != sender_conn:
                try:
                    conn.sendall(data_bytes + b"\n")
                except Exception:
                    pass

def handle_handshake(conn, packet):
    method = packet.get("method")
    step = packet.get("step")
    state = clients[conn]["handshake_state"]
    client_id = clients[conn]["id"]

    if step == "INIT":
        state["t_start"] = time.perf_counter()
        state["method"] = method

        if method == "RSA":
            priv, pub, t, sz = CryptoService.generate_rsa_keypair()
        elif method == "ECC":
            priv, pub, t, sz = CryptoService.generate_ecc_keypair()
        elif method == "DH":
            priv, pub, t, sz = CryptoService.generate_dh_keypair()
        elif method == "KYBER":
            priv, pub, t, sz = CryptoService.generate_kyber_keypair()

        state["priv"] = priv
        resp = {
            "type": "HANDSHAKE", "method": method, "step": "SERVER_PUB", "pub_key": pub,
            "metrics": {"gen_time_ms": round(t, 2), "pub_size_bytes": sz}
        }
        conn.sendall((json.dumps(resp) + "\n").encode('utf-8'))

    elif step == "FINALIZE":
        payload = packet.get("payload")
        if method == "RSA":
            clients[conn]["aes_key"] = CryptoService.rsa_decrypt_aes_key(state["priv"], payload)
        elif method == "ECC":
            clients[conn]["aes_key"] = CryptoService.ecc_shared_key(state["priv"], payload)
        elif method == "DH":
            clients[conn]["aes_key"] = CryptoService.dh_shared_key(state["priv"], payload)
        elif method == "KYBER":
            clients[conn]["aes_key"] = CryptoService.kyber_decaps(state["priv"], payload)

        total_t = (time.perf_counter() - state.get("t_start", time.perf_counter())) * 1000
        resp = {
            "type": "HANDSHAKE_OK", "method": method,
            "metrics": {"handshake_time_ms": round(total_t, 2), "incoming_bytes": len(str(payload))}
        }
        conn.sendall((json.dumps(resp) + "\n").encode('utf-8'))

def handle_client(conn, addr):
    client_id = f"Client_{addr[1]}"
    with client_lock:
        clients[conn] = {"id": client_id, "aes_key": None, "handshake_state": {}}

    buffer = ""
    try:
        while True:
            data = conn.recv(8192).decode('utf-8', errors='ignore')
            if not data:
                break
            buffer += data
            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                if not line.strip():
                    continue

                packet = json.loads(line.strip())
                if packet.get("type") == "HANDSHAKE":
                    handle_handshake(conn, packet)
                    continue

                mode = packet.get("mode")
                if mode == "UNENCRYPTED":
                    forward_packet(conn, line.strip().encode('utf-8'))
                elif mode == "ENCRYPTED":
                    sender_key = clients[conn]["aes_key"]
                    if not sender_key:
                        continue

                    # Mesajı çöz ve diğer istemcilere onların anahtarıyla şifreleyip ilet
                    plain = CryptoService.aes_decrypt(sender_key, packet["payload"])
                    with client_lock:
                        for oc in [c for c in clients if c != conn]:
                            target_key = clients[oc]["aes_key"]
                            if target_key:
                                re_enc = CryptoService.aes_encrypt(target_key, plain)
                                out = {"type": "TEXT", "mode": "ENCRYPTED", "sender": client_id, "payload": re_enc}
                                oc.sendall((json.dumps(out) + "\n").encode('utf-8'))
    except Exception:
        pass
    finally:
        with client_lock:
            if conn in clients:
                del clients[conn]
        conn.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"[*] Minimal Kripto Sunucu Dinlemede: {HOST}:{PORT}")
    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    start_server()