"""
import os
import sys
import site
sys.path.append(site.getusersitepackages())
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC

try:
    from pqcrypto.kem import kyber768
except ImportError:
    print("BURAYA GİRLDİ")
    kyber768 = None
class CryptoService:

    #AES
    @staticmethod
    def generate_aes_key() -> bytes:
        return os.urandom(16)#16 byte (128 bit) rastgele anahtar üret

    @staticmethod
    def aes_encrypt(key:bytes,plaintext:bytes) -> bytes:
        cipher = AES.new(key,AES.MODE_CBC)
        ciphertext = cipher.encrypt(pad(plaintext,AES.block_size))
        return cipher.iv + ciphertext#AES-128-CBC ile veriyi şifrele. sonra iv(16 byte) + şifreli metini döndür

    @staticmethod
    def aes_decrypt(key:bytes,encrypted_payload:bytes) -> bytes:
        iv_degeri = encrypted_payload[:16]#payload = iv(16 byte) + chipertext ilk 16 bytelık kısım...
        ciphertext = encrypted_payload[16:]
        cipher = AES.new(key,AES.MODE_CBC,iv=iv_degeri)
        return unpad(cipher.decrypt(ciphertext),AES.block_size)#veriyi çöz
        
    #RSA-2048
    @staticmethod
    def generate_rsa_keypair():#private key,public key
        key = RSA.generate(2048)
        return key,key.public_key()

    @staticmethod
    def rsa_encrypt_aes_key(public_key,aes_key:bytes) -> bytes:
        #client:aes anahtarını public key ile şifreler
        cipher_rsa = PKCS1_OAEP.new(public_key)#şifrele
        return cipher_rsa.encrypt(aes_key)

    @staticmethod
    def rsa_decrypt_aes_key(private_key,encrypted_aes_key:bytes) -> bytes:
        #alıcı:gelen şifreli aes anahtarını sadece kendinde bulunana rsa private key'i ile çözer
        cipher_rsa = PKCS1_OAEP.new(private_key)
        return cipher_rsa.decrypt(encrypted_aes_key)


    #DH-2048
    ##standart sabitler
    DH_P = int(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
        "FFFFFFFFFFFFFFFF", 16
    )#16'lık tabanda güvenli asal sayı
    DH_G = 2#generator

    @classmethod
    def generate_dh_keypair(cls):
        private_key = int.from_bytes(os.urandom(32), byteorder='big')#256 bit
        public_key = pow(cls.DH_G, private_key, cls.DH_P)#public_key
        return private_key, public_key

    @classmethod
    def dh_shared_key(cls, private_key: int, public_key: int) -> bytes:
        shared_secret_int = pow(public_key, private_key, cls.DH_P)
        shared_secret_bytes = shared_secret_int.to_bytes(256, byteorder='big')
        return HKDF(shared_secret_bytes, 16, b'', SHA256)



    #ecc/edhc
    @staticmethod
    def generate_ecc_keypair():
        private_key = ECC.generate(curve='P-256')
        public_key  = private_key.public_key()
        return private_key,public_key#ecc anahtar çifti

    @staticmethod
    def ecc_shared_key(private_key,public_key) -> bytes:
        shared_point = private_key.d * public_key.pointQ
        shared_secret = int(shared_point.x).to_bytes(32,byteorder='big')
        aes_key = HKDF(shared_secret,16, b'',SHA256)
        return aes_key#private key + ecc public key = aes anahtarı


#kyber 768 eklenecek...

"""

import os
import sys
import base64
import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC

import pqcrypto.kem.ml_kem_768 as kyber768
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

class CryptoService:

    # ================= AES-128 (CBC MODU + PKCS7) =================
    @staticmethod
    def generate_aes_key() -> bytes:
        return os.urandom(16)  # 16 byte (128 bit)
    
    @staticmethod
    def aes_encrypt(key: bytes, plaintext: str) -> dict:
        iv = os.urandom(16)
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()

        cipher = Cipher(algorithms.AES(key[:16]), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        return {
            "iv": base64.b64encode(iv).decode('utf-8'),
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
        }

    @staticmethod
    def aes_decrypt(key: bytes, payload_dict: dict) -> str:
        iv = base64.b64decode(payload_dict["iv"])
        ciphertext = base64.b64decode(payload_dict["ciphertext"])

        cipher = Cipher(algorithms.AES(key[:16]), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        return data.decode('utf-8')

    # ================= RSA-2048 =================
    @staticmethod
    def generate_rsa_keypair():
        t0 = time.perf_counter()
        key = RSA.generate(2048)
        gen_time = (time.perf_counter() - t0) * 1000
        pub_pem = key.public_key().export_key(format='PEM').decode('utf-8')
        return key, pub_pem, gen_time, len(pub_pem.encode('utf-8'))

    @staticmethod
    def rsa_encrypt_aes_key(public_key_pem: str, aes_key: bytes) -> str:
        pub_key = RSA.import_key(public_key_pem)
        cipher_rsa = PKCS1_OAEP.new(pub_key, hashAlgo=SHA256)
        enc_secret = cipher_rsa.encrypt(aes_key)
        return base64.b64encode(enc_secret).decode('utf-8')

    @staticmethod
    def rsa_decrypt_aes_key(private_key, enc_secret_b64: str) -> bytes:
        enc_secret = base64.b64decode(enc_secret_b64)
        cipher_rsa = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
        return cipher_rsa.decrypt(enc_secret)

    # ================= DIFFIE-HELLMAN (DH 2048) =================
    DH_P = int(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
        "FFFFFFFFFFFFFFFF", 16
    )
    DH_G = 2

    @classmethod
    def generate_dh_keypair(cls):
        t0 = time.perf_counter()
        private_key = int.from_bytes(os.urandom(32), byteorder='big')
        public_key = pow(cls.DH_G, private_key, cls.DH_P)
        gen_time = (time.perf_counter() - t0) * 1000
        pub_hex = hex(public_key)
        return private_key, pub_hex, gen_time, len(pub_hex)

    @classmethod
    def dh_shared_key(cls, private_key: int, client_pub_hex: str) -> bytes:
        client_pub = int(client_pub_hex, 16)
        shared_secret_int = pow(client_pub, private_key, cls.DH_P)
        shared_secret_bytes = shared_secret_int.to_bytes(256, byteorder='big')
        return HKDF(shared_secret_bytes, 16, b'', SHA256)

    # ================= ECC (ECDH SECP256R1 / P-256) =================
    @staticmethod
    def generate_ecc_keypair():
        t0 = time.perf_counter()
        private_key = ECC.generate(curve='P-256')
        gen_time = (time.perf_counter() - t0) * 1000
        pub_pem = private_key.public_key().export_key(format='PEM')
        return private_key, pub_pem, gen_time, len(pub_pem.encode('utf-8'))

    @staticmethod
    def ecc_shared_key(private_key, client_pub_pem: str) -> bytes:
        client_pub = ECC.import_key(client_pub_pem)
        shared_point = private_key.d * client_pub.pointQ
        shared_secret = int(shared_point.x).to_bytes(32, byteorder='big')
        return HKDF(shared_secret, 16, b'', SHA256)

    # ================= KYBER (ML-KEM-768 - POST-QUANTUM) =================
    @staticmethod
    def generate_kyber_keypair():
        t0 = time.perf_counter()
        public_key, secret_key = kyber768.keygen()
        gen_time = (time.perf_counter() - t0) * 1000
        pub_b64 = base64.b64encode(public_key).decode('utf-8')
        return secret_key, pub_b64, gen_time, len(public_key)

    @staticmethod
    def kyber_decaps(secret_key, ciphertext_b64: str) -> bytes:
        ciphertext = base64.b64decode(ciphertext_b64)
        shared_secret = kyber768.decaps(secret_key, ciphertext)
        return shared_secret[:16]

    @staticmethod
    def kyber_encaps(server_pub_b64: str):
        server_pub = base64.b64decode(server_pub_b64)
        ciphertext, shared_secret = kyber768.encaps(server_pub)
        return base64.b64encode(ciphertext).decode('utf-8'), shared_secret[:16]