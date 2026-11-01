from app.services.kriptogramAES import KriptogramAES

class ManualCryptoService:
    
    @staticmethod
    def encrypt_message(plaintext: str, aes_key: bytes) -> bytes:
        return KriptogramAES.encrypt_text(plaintext, aes_key)

    @staticmethod
    def decrypt_message(ciphertext: bytes, aes_key: bytes) -> str:
        return KriptogramAES.decrypt_text(ciphertext, aes_key)


        """
        
        # Örnek Kullanım
anahtar = b"0123456789abc3ef" 
mesaj = "Bu mesaj manuel KriptogramAES ile şifreleniyor!"

# Şifreleme
sifreli_veri = ManualCryptoService.encrypt_message(mesaj, anahtar)
print(f"Şifreli (Hex): {sifreli_veri.hex()}")

# Çözme
cozulmus_mesaj = ManualCryptoService.decrypt_message(sifreli_veri, anahtar)
print(f"Çözülen Metin: {cozulmus_mesaj}")
        """