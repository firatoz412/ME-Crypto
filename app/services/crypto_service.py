import os
import sys
import site
import time
import base64
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
    def aes_encrypt(key:bytes,plaintext:str) -> dict:
        
        if isinstance(plaintext,str):
            plaintext = plaintext.encode('utf-8')
            
        cipher = AES.new(key,AES.MODE_CBC)
        ciphertext = cipher.encrypt(pad(plaintext,AES.block_size))
        
        return {
            "iv": base64.b64encode(cipher.iv).decode('utf-8'),
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
            "raw": cipher.iv + ciphertext
        }

    @staticmethod
    def aes_decrypt(key:bytes,encrypted_payload:bytes) -> bytes:
        iv_degeri = encrypted_payload[:16]#payload = iv(16 byte) + chipertext ilk 16 bytelık kısım...
        ciphertext = encrypted_payload[16:]
        cipher = AES.new(key,AES.MODE_CBC,iv=iv_degeri)
        return unpad(cipher.decrypt(ciphertext),AES.block_size)#veriyi çöz
        
    #RSA-2048
    @staticmethod
    def generate_rsa_keypair():#private key,public key,generator time,public key size
        start_time = time.perf_counter()
        key = RSA.generate(2048)
        pub_pem = key.publickey().export_key().decode('utf-8')
        gen_time = (time.perf_counter() - start_time)*1000
        pub_size = len(pub_pem.encode('utf-8'))
        return key,pub_pem,gen_time,pub_size
    
    
    @staticmethod
    def load_rsa_public_key(pem):
        return RSA.import_key(pem)
    

    @staticmethod
    def rsa_encrypt_aes_key(public_key,aes_key:bytes) -> bytes:
        #client:aes anahtarını sunucunun public key'i ile şifreler
        return PKCS1_OAEP.new(public_key).encrypt(aes_key)
        

    @staticmethod
    def rsa_decrypt_aes_key(private_key,encrypted_aes_key:bytes) -> bytes:
        #alıcı:gelen şifreli aes anahtarını sadece kendinde bulunana rsa private key'i ile çözer
        return PKCS1_OAEP.new(private_key).decrypt(encrypted_aes_key)


    #DH-2048
    #standart sabitler
    DH_P = int(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
        "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
    )#16'lık tabanda güvenli asal sayı (2048 bit)
    DH_G = 2#generator

    @classmethod#priv, pub_hex, gen_time, pub_size 
    def generate_dh_keypair(cls):
        start_time = time.perf_counter()
        private_key = int.from_bytes(os.urandom(32), byteorder='big')#256 bit
        public_key = pow(cls.DH_G, private_key, cls.DH_P)#public_key
        pub_hex = hex(public_key)[2:]
        gen_time = (time.perf_counter() - start_time) * 1000
        pub_size = len(pub_hex.encode('utf-8'))
        return private_key,pub_hex,gen_time,pub_size
    
    @classmethod
    def load_dh_public_key(cls,pub_hex:str) -> int:
        y = int(pub_hex, 16)
        
        if not (1 < y < cls.DH_P - 1):
            raise ValueError("geçersiz DH açık değeri")
        
        return y
    

    @classmethod
    def dh_shared_key(cls, private_key: int, public_key: int) -> bytes:
        
        if not (1 < public_key < cls.DH_P -1):#zorunlu public key sınırı
            raise ValueError("geçersiz DH açık değeri")
        
        shared_secret_int = pow(public_key, private_key, cls.DH_P)
        shared_secret_bytes = shared_secret_int.to_bytes(256, byteorder='big')
        return HKDF(shared_secret_bytes, 16, b'', SHA256)



    #ecc/edhc
    @staticmethod
    def generate_ecc_keypair():
        
        start_time = time.perf_counter()
        private_key = ECC.generate(curve='P-256')
        public_key  = private_key.public_key()
        pub_pem = public_key.export_key(format='PEM')
            
        gen_time = (time.perf_counter() - start_time)*1000
        pub_size = len(pub_pem.encode('utf-8'))
        
        return private_key,pub_pem,gen_time,pub_size


    @staticmethod
    def load_ecc_public_key(pem):
        return ECC.import_key(pem)
    

    @staticmethod
    def ecc_shared_key(private_key,public_key) -> bytes:
        shared_point = private_key.d * public_key.pointQ
        shared_secret = int(shared_point.x).to_bytes(32,byteorder='big')
        aes_key = HKDF(shared_secret,16, b'',SHA256)
        return aes_key#private key + ecc public key = aes anahtarı


    #kyber
    @staticmethod#priv(secret), pub_b64, gen_time, pub_size
    def generate_kyber_keypair():
        start_time = time.perf_counter()
        public_key, private_key = ml_kem_768.keygen()#public,secret
        pub_b64 = base64.b64encode(public_key).decode('utf-8')
        gen_time = (time.perf_counter() - start_time)*1000
        pub_size = len(pub_b64.encode('utf-8'))
        return private_key,pub_b64,gen_time,pub_size
    
    
    @staticmethod
    def kyber_to_aes_key(shared_secret: bytes) -> bytes:
        return HKDF(shared_secret, 16, b'', SHA256)#ml-kem'in ortak sırrı 32 bayt,aes için 16 bayta indir.


    @classmethod
    def kyber_encapsulate(cls,public_key: bytes):
        #istemci: (ciphertext, aes_key_16bayt) döner, ciphertext sunucuya gider
        a, b = ml_kem_768.encaps(public_key)
        ciphertext, shared_secret = (a, b) if len(a) > len(b) else (b, a)
        return ciphertext, cls.kyber_to_aes_key(shared_secret)


    @classmethod
    def kyber_decapsulate(cls,secret_key: bytes, ciphertext: bytes) -> bytes:
        shared_secret = ml_kem_768.decaps(secret_key, ciphertext)
        return cls.kyber_to_aes_key(shared_secret)
    
    
