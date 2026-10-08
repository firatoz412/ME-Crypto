import socket
import json
import base64
import time
from crypto_engine import CryptoEngine
import pqcrypto.kem.ml_kem_768 as kyber768

SERVER_IP = "127.0.0.1"
PORT = 5000

engine = CryptoEngine()

def run_test():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((SERVER_IP, PORT))
    print("[+] 1. Sunucuya TCP soket bağlantısı kuruldu.")

    # 1. Aşama: Kyber El Sıkışmasını Başlat (INIT)
    req = {"type": "HANDSHAKE", "method": "KYBER", "step": "INIT"}
    s.sendall((json.dumps(req) + "\n").encode('utf-8'))

    # Sunucudan gelen Kyber Public Key'i al
    resp_raw = s.recv(8192).decode('utf-8').strip()
    resp = json.loads(resp_raw)
    server_pub_bytes = base64.b64decode(resp["pub_key"])
    print(f"[+] 2. Sunucunun Kyber Açık Anahtarı alındı ({len(server_pub_bytes)} byte).")

   # İstemci tarafında kapsülleme yap
    ciphertext, shared_secret = kyber768.encaps(server_pub_bytes)
    aes_key = shared_secret[:16]
    print(f"[+] 3. Kyber Kapsülleme yapıldı. Ortak AES-128 Anahtarı belirlendi: {aes_key.hex()[:8]}...")

    # Sunucuya ciphertext'i yolla (FINALIZE)
    finalize_req = {
        "type": "HANDSHAKE",
        "method": "KYBER",
        "step": "FINALIZE",
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
    }
    s.sendall((json.dumps(finalize_req) + "\n").encode('utf-8'))

    # Sunucudan onay bekle
    s.recv(1024)
    print("[✓] 4. El sıkışma başarıyla tamamlandı!")

    # 2. Aşama: AES-128 ile Şifreli Mesaj Gönder
    gizli_mesaj = "bu mesaj AES-128 ve Kyber-768 ile korunuyor!"
    encrypted_payload = engine.encrypt_aes(aes_key, gizli_mesaj)

    msg_packet = {
        "type": "TEXT",
        "mode": "ENCRYPTED",
        "payload": encrypted_payload
    }
    s.sendall((json.dumps(msg_packet) + "\n").encode('utf-8'))
    print(f"[+] 5. Şifreli mesaj sunucuya yollandı: {encrypted_payload['ciphertext'][:20]}...")

    time.sleep(1)
    s.close()
    print("[+] Test bitti, bağlantı kapatıldı.")

if __name__ == "__main__":
    run_test()