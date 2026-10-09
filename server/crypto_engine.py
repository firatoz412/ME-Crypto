import os
import time
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dh, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import pqcrypto.kem.ml_kem_768 as kyber768

class CryptoEngine:
    def __init__(self):
        # Ortak DH grubu parametresi (RFC 3526 modp 2048)
        self.dh_parameters = dh.generate_parameters(generator=2, key_size=2048)

    #RSA (2048)
    def generate_rsa_keypair(self):
        t0 = time.perf_counter()
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        gen_time = (time.perf_counter() - t0) * 1000
        pub_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return private_key, pub_bytes.decode('utf-8'), gen_time, len(pub_bytes)

    def decrypt_rsa_secret(self, private_key, enc_secret_bytes):
        return private_key.decrypt(
            enc_secret_bytes,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    # ECC (ECDH SECP256R1)
    def generate_ecc_keypair(self):
        t0 = time.perf_counter()
        private_key = ec.generate_private_key(ec.SECP256R1())
        gen_time = (time.perf_counter() - t0) * 1000
        pub_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return private_key, pub_bytes.decode('utf-8'), gen_time, len(pub_bytes)

    def derive_ecc_secret(self, private_key, client_pub_pem):
        client_pub = serialization.load_pem_public_key(client_pub_pem.encode('utf-8'))
        shared_key = private_key.exchange(ec.ECDH(), client_pub)
        return HKDF(
            algorithm=hashes.SHA256(),
            length=16,
            salt=None,
            info=b'handshake data'
        ).derive(shared_key)
    
   # DIFFIE-HELLMAN (DH 2048) 
    def generate_dh_keypair(self):
        t0 = time.perf_counter()
        private_key = self.dh_parameters.generate_private_key()
        gen_time = (time.perf_counter() - t0) * 1000
        
        # Public Key
        pub_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        # Ortak DH Parametreleri (p ve g değerleri)
        param_bytes = self.dh_parameters.parameter_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.ParameterFormat.PKCS3
        )
        return private_key, pub_bytes.decode('utf-8'), param_bytes.decode('utf-8'), gen_time, len(pub_bytes)

    def derive_dh_secret(self, private_key, client_pub_pem):
        client_pub = serialization.load_pem_public_key(client_pub_pem.encode('utf-8'))
        shared_key = private_key.exchange(client_pub)
        return HKDF(
            algorithm=hashes.SHA256(),
            length=16,
            salt=None,
            info=b'handshake data'
        ).derive(shared_key)

    #  KYBER (ML-KEM-768)
    def generate_kyber_keypair(self):
        t0 = time.perf_counter()
        public_key, secret_key = kyber768.keygen()
        gen_time = (time.perf_counter() - t0) * 1000
        return secret_key, base64.b64encode(public_key).decode('utf-8'), gen_time, len(public_key)

    # AES-128 (CBC MODU + PKCS7)
    @staticmethod
    def encrypt_aes(key: bytes, plaintext: str) -> dict:
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key[:16]), modes.CBC(iv))
        encryptor = cipher.encryptor()
        
        data = plaintext.encode('utf-8')
        pad_len = 16 - (len(data) % 16)
        data += bytes([pad_len] * pad_len)
        
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return {
            "iv": base64.b64encode(iv).decode('utf-8'),
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
        }

    @staticmethod
    def decrypt_aes(key: bytes, payload_dict: dict) -> str:
        iv = base64.b64decode(payload_dict["iv"])
        ciphertext = base64.b64decode(payload_dict["ciphertext"])
        
        cipher = Cipher(algorithms.AES(key[:16]), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
        
        pad_len = decrypted_padded[-1]
        decrypted = decrypted_padded[:-pad_len]
        return decrypted.decode('utf-8')