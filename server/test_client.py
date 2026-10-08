import socket
import json
import base64
import time
from crypto_engine import CryptoEngine
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dh, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import pqcrypto.kem.ml_kem_768 as kyber768

SERVER_IP = "127.0.0.1"
PORT = 5000
engine = CryptoEngine()

def test_handshake(method_name):
    print(f"\n>>> [{method_name}] Testi Başlatılıyor...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((SERVER_IP, PORT))

    # INIT İsteği
    req = {"type": "HANDSHAKE", "method": method_name, "step": "INIT"}
    s.sendall((json.dumps(req) + "\n").encode('utf-8'))

    # Sunucu Public Key Yanıtı
    resp = json.loads(s.recv(16384).decode('utf-8').strip())
    server_pub = resp["pub_key"]

    aes_key = None
    finalize_payload = None

    if method_name == "RSA":
        client_aes = b"1234567890123456"  # 16-byte AES-128
        pub_key_obj = serialization.load_pem_public_key(server_pub.encode('utf-8'))
        enc_secret = pub_key_obj.encrypt(
            client_aes,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        aes_key = client_aes
        finalize_payload = base64.b64encode(enc_secret).decode('utf-8')

    elif method_name == "ECC":
        client_priv = ec.generate_private_key(ec.SECP256R1())
        client_pub_bytes = client_priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        server_pub_obj = serialization.load_pem_public_key(server_pub.encode('utf-8'))
        shared_key = client_priv.exchange(ec.ECDH(), server_pub_obj)
        aes_key = HKDF(algorithm=hashes.SHA256(), length=16, salt=None, info=b'handshake data').derive(shared_key)
        finalize_payload = client_pub_bytes.decode('utf-8')

    elif method_name == "DH":
        # Sunucunun yolladığı ortak DH parametresini yükle
        dh_params = serialization.load_pem_parameters(resp["dh_params"].encode('utf-8'))
        client_priv = dh_params.generate_private_key()
        client_pub_bytes = client_priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        server_pub_obj = serialization.load_pem_public_key(server_pub.encode('utf-8'))
        shared_key = client_priv.exchange(server_pub_obj)
        aes_key = HKDF(algorithm=hashes.SHA256(), length=16, salt=None, info=b'handshake data').derive(shared_key)
        finalize_payload = client_pub_bytes.decode('utf-8')

    elif method_name == "KYBER":
        ciphertext, shared_secret = kyber768.encaps(base64.b64decode(server_pub))
        aes_key = shared_secret[:16]
        finalize_payload = base64.b64encode(ciphertext).decode('utf-8')

    # FINALIZE İsteği
    finalize_req = {
        "type": "HANDSHAKE",
        "method": method_name,
        "step": "FINALIZE",
        "payload": finalize_payload
    }
    s.sendall((json.dumps(finalize_req) + "\n").encode('utf-8'))
    s.recv(1024)

    # 3. AES-128 Şifreli Mesaj Testi
    gizli_mesaj = f"{method_name} ve AES-128 ile sifreli iletisim basarili."
    enc_dict = engine.encrypt_aes(aes_key, gizli_mesaj)
    msg_packet = {"type": "TEXT", "mode": "ENCRYPTED", "payload": enc_dict}
    s.sendall((json.dumps(msg_packet) + "\n").encode('utf-8'))

    time.sleep(0.5)
    s.close()
    print(f"[✓] [{method_name}] Testi Tamamlandı!")

if __name__ == "__main__":
    for alg in ["RSA", "ECC", "DH", "KYBER"]:
        test_handshake(alg)
        time.sleep(0.3)