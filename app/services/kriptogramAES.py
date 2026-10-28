import os

class KriptogramAES:


    #standart güvenilir sabit matrisler
    S_BOX = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    ]

    INVERTS_BOX = [
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    ]

    #Rijndael Şifreleme Sabitleri (Galois Field Çarpımları için)
    #Round Constant = anahtar genişletme fonksiyonunda(expand_key():) g fonksiyonu bölümünde
    #4 byte'lık dizinin sadece ilk baytı rcon sabitleri ile xorlarnır
    #örnek = [b0 +RCON[x.ci round],b1,b2,b3]    
    RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]


    """
        #satır öncelikli
          return [
                    state[0],  state[1],  state[2], state[3],
                    state[5],  state[6],  state[7], state[4],
                    state[10],  state[11], state[8],  state[9],
                    state[15], state[12],  state[13],  state[14]
            ]
    """
    #sütun öncelikli:
    @staticmethod
    def shift_rows(state):
        return [
            state[0],  state[5],  state[10], state[15],
            state[4],  state[9],  state[14], state[3],
            state[8],  state[13], state[2],  state[7],
            state[12], state[1],  state[6],  state[11]
        ]

    @staticmethod
    def inv_shift_rows(state):
        return [
            state[0],  state[13], state[10], state[7],
            state[4],  state[1],  state[14], state[11],
            state[8],  state[5],  state[2],  state[15],
            state[12], state[9],  state[6],  state[3]
        ]

    @staticmethod
    def _sub_bytes(state):
        return [KriptogramAES.S_BOX[b] for b in state]#Her baytı S_Box tablosundaki karşılığı ile değiştirir.

    @staticmethod
    def _inv_sub_bytes(state):
        return [KriptogramAES.INVERTS_BOX[b] for b in state]#Her baytı ters S_Box tablosundaki karşılığı ile değiştirir.

    @staticmethod
    def _add_round_key(state, key):
        #veri ve anahtarı xorlar.
        return [s ^ k for s, k in zip(state, key)]

    @staticmethod
    def _galois_mult(a, b):
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            hi_bit_set = a & 0x80
            a = (a << 1) & 0xFF
            if hi_bit_set:
                a ^= 0x1b
            b >>= 1
        return p

    @staticmethod
    def mix_columns(state):
        new_state = list(state)
        for i in range(4):
            col = i * 4#her sütunun başlangıçlarını alıyoruz.(0,4,8,12)
            s0, s1, s2, s3 = state[col], state[col+1], state[col+2], state[col+3]#i=0 -> s0,s1,s2,s3 = col[0],col[1],col[2],col[3]...
            new_state[col]   = KriptogramAES._galois_mult(s0, 2) ^ KriptogramAES._galois_mult(s1, 3) ^ s2 ^ s3
            new_state[col+1] = s0 ^ KriptogramAES._galois_mult(s1, 2) ^ KriptogramAES._galois_mult(s2, 3) ^ s3
            new_state[col+2] = s0 ^ s1 ^ KriptogramAES._galois_mult(s2, 2) ^ KriptogramAES._galois_mult(s3, 3)
            new_state[col+3] = KriptogramAES._galois_mult(s0, 3) ^ s1 ^ s2 ^ KriptogramAES._galois_mult(s3, 2)
        return new_state

    @staticmethod
    def inv_mix_columns(state):
        new_state = list(state)
        for i in range(4):
            col = i * 4
            s0, s1, s2, s3 = state[col], state[col+1], state[col+2], state[col+3]
            new_state[col]   = KriptogramAES._galois_mult(s0, 14) ^ KriptogramAES._galois_mult(s1, 11) ^ KriptogramAES._galois_mult(s2, 13) ^ KriptogramAES._galois_mult(s3, 9)
            new_state[col+1] = KriptogramAES._galois_mult(s0, 9)  ^ KriptogramAES._galois_mult(s1, 14) ^ KriptogramAES._galois_mult(s2, 11) ^ KriptogramAES._galois_mult(s3, 13)
            new_state[col+2] = KriptogramAES._galois_mult(s0, 13) ^ KriptogramAES._galois_mult(s1, 9)  ^ KriptogramAES._galois_mult(s2, 14) ^ KriptogramAES._galois_mult(s3, 11)
            new_state[col+3] = KriptogramAES._galois_mult(s0, 11) ^ KriptogramAES._galois_mult(s1, 13) ^ KriptogramAES._galois_mult(s2, 9)  ^ KriptogramAES._galois_mult(s3, 14)
        return new_state

    @classmethod
    def expand_key(cls, master_key: bytes):
        cls.check_key(master_key)
        key_words = [list(master_key[i:i+4]) for i in range(0, 16, 4)]
        for i in range(4, 44):
            temp = list(key_words[i-1])
            if i % 4 == 0:
                temp = temp[1:] + temp[:1]  #RotWord = byte'ları sola kaydırır [b1,b2,b3,b4] ---rotword--> [b2,b3,b4,b1]
                temp = [cls.S_BOX[b] for b in temp]  #SubWord = s_box ile yer değiştir.
                temp[0] ^= cls.RCON[(i // 4) - 1]  # Rcon = ilk byte a xor.
            
            new_word = [a ^ b for a, b in zip(key_words[i-4], temp)]
            key_words.append(new_word)
        
        round_keys = []
        for r in range(11):
            r_key = []
            for c in range(4):
                r_key.extend(key_words[r * 4 + c])
            round_keys.append(r_key)
        return round_keys
    
    @staticmethod
    def check_key(key):
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("anahtar bytes tipinde olmalı")
        if len(key) != 16:
            raise ValueError("AES-128 anahtarı 16 byte olmalı")

    @staticmethod
    def check_block(block):
        if not isinstance(block, (bytes, bytearray)):
            raise TypeError("blok bytes tipinde olmalı")
        if len(block) != 16:
            raise ValueError("blok 16 bayt olmalı")

    @classmethod
    def encrypt_block(cls, plaintext_block: bytes, key: bytes,round_keys=None) -> bytes:
        
        cls.check_block(plaintext_block)
        cls.check_key(key)
        
        if round_keys is None:
            round_keys = cls.expand_key(key)

        state = list(plaintext_block)
        state = cls._add_round_key(state,round_keys[0])
        
        for r in range(1, 10):
            state = cls._sub_bytes(state)
            state = cls.shift_rows(state)
            state = cls.mix_columns(state)
            state = cls._add_round_key(state, round_keys[r])
        
        #son adımda round key eklemiyoruz;
        state = cls._sub_bytes(state)
        state = cls.shift_rows(state)
        state = cls._add_round_key(state, round_keys[10])
        return bytes(state)

    @classmethod
    def decrypt_block(cls, ciphertext_block: bytes, key: bytes,round_keys=None) -> bytes:
        
        cls.check_block(ciphertext_block)
        cls.check_key(key)
       
        if round_keys is None:
            round_keys = cls.expand_key(key)
            
        state = list(ciphertext_block)
        state = cls._add_round_key(state, round_keys[10])
        state = cls.inv_shift_rows(state)
        state = cls._inv_sub_bytes(state)
        
        for r in range(9, 0, -1):
            state = cls._add_round_key(state, round_keys[r])
            state = cls.inv_mix_columns(state)
            state = cls.inv_shift_rows(state)
            state = cls._inv_sub_bytes(state)
            
        state = cls._add_round_key(state, round_keys[0])
        return bytes(state)
    
    
    @staticmethod
    def pad(data: bytes) -> bytes:
        
        if not isinstance(data,bytes):
            raise TypeError("data byte tipinde olmalı")
        
        block_size = 16
        padding_len = block_size - (len(data)%16)#doldurulacak padding boyutu hesabı
        padding =  bytes([padding_len]*padding_len)#Örnek: data = 10,padding lentgh(pl) = 6 -> return data + [pl]*pl -> return data + [pl,pl,pl,pl,pl,pl] -> dataplplplplplpl
        
        return data + padding
    
    
    @staticmethod
    def unpad(data:bytes) -> bytes:
        
        if not data or len(data) % 16 != 0:
            raise ValueError("geçersiz veri uzunluğu")
        
        padding_len = data[-1]
        
        if padding_len < 1 or padding_len > 16:
            raise ValueError("geçersiz padding uzunluğu")
        
        if data[-padding_len:] != bytes([padding_len]) * padding_len:
            raise ValueError("geçersiz padding")
        
        return data[:-padding_len]
    
    
    #CBC:dönene değer = iv(16 bayt) + ciphertext
    @classmethod
    def encrypt_cbc(cls, data: bytes, key: bytes, iv: bytes = None) -> bytes:
        
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("data bytes tipinde olmalı")
        
        if iv is None:
            iv = os.urandom(16)
            
        cls.check_block(iv)
        round_keys = cls.expand_key(key)
        padded = cls.pad(bytes(data))
        prev, out = bytes(iv), bytearray()
        
        for i in range(0, len(padded), 16):
            block = bytes(a ^ b for a, b in zip(padded[i:i + 16], prev))
            prev = cls.encrypt_block(block, key, round_keys)
            out.extend(prev)
            
        return bytes(iv) + bytes(out)
    
    
    
 
    @classmethod
    def decrypt_cbc(cls, payload: bytes, key: bytes) -> bytes:
        
        if not isinstance(payload, (bytes, bytearray)):
            raise TypeError("payload bytes tipinde olmalı")
        
        if len(payload) < 32 or len(payload) % 16 != 0:
            raise ValueError("payload = iv(16) + ciphertext(16'nın katı) olmalı")
        
        iv, ct = bytes(payload[:16]), bytes(payload[16:])
        round_keys = cls.expand_key(key)
        prev, out = iv, bytearray()
        
        for i in range(0, len(ct), 16):
            c = ct[i:i + 16]
            d = cls.decrypt_block(c, key, round_keys)
            out.extend(a ^ b for a, b in zip(d, prev))
            prev = c
            
        return cls.unpad(bytes(out))
    
    
    
    @classmethod
    def encrypt_text(cls,plaintext:str,key:bytes) -> bytes:
        
        if not isinstance(plaintext,str):
            raise TypeError("plaintext string tipinde olmalı.")
        
        return cls.encrypt_cbc(plaintext.encode("utf-8"),key)
    
    
    @classmethod
    def decrypt_text(cls,ciphertext_block:bytes,key:bytes) -> str:
        
        if not isinstance(ciphertext_block, (bytes, bytearray)):
            raise TypeError("şifreli veri bytes tipinde olmalı")
        
        return cls.decrypt_cbc(ciphertext_block,key).decode("utf-8")
    
        
    
       
       