import os
import sys
import site
sys.path.append(site.getusersitepackages())
from Crypto.PublicKey import RSA,ECC
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from pqcrypto.kem import ml_kem_768


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


    #kyber
    @staticmethod
    def generate_kyber_keypair():
        public_key, secret_key = ml_kem_768.keygen()
        return secret_key, public_key

    @staticmethod
    def kyber_encapsulate(public_key: bytes):
        return ml_kem_768.encaps(public_key)

    @staticmethod
    def kyber_decapsulate(secret_key: bytes, ciphertext: bytes) -> bytes:
        return ml_kem_768.decaps(secret_key, ciphertext)
