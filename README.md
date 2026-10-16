ME-Crypto(Multiple-Encryption Crypto)


->Bu proje sunucu-istemci(server-client) mimarisine dayanan, 4 farklı anahtar değişim protokolünü kullanarak (RSA,DH,ECC VE Kyber) güvenli
bir şekilde mesajlaşma,PDF ve resim transferi yapabilen bir web uygulamasıdır.Uygulamada AES-128 şifrelene mekanizmasının hem hazır kütüphane 
ile hem de kütüphanesiz,sıfırdan yazılmış haliyle barındırır.


->Kullanlılan teknoljiler:
   Backend:

      ->Pyhton 3.13.7

   Frontend:

      ->HTML
      ->CSS
      ->JS

Projenin Temel Amacı ve Özellikleri:

   ->Sunucu ve istemci arasında mesajlaşma,dosya transferleri.

   ->Güvenli Mod ve Güvensiz Mod olmak üzere iki ayrı çalşma modu.

      ->Güvensiz Mod:Veriler şifrelenmeden düz metin olarak iletilir.(wireshark ile okunabilir)

      ->Güvenli Mod:Veriler AES anahtarı ile şifrelenir ve bu anahtar kullanıcının seçtiği 4 farklı anahtar değişim protokolü ile iletilir.
   ->Dört farklı anahtar değişim protokolünden biri seçilebilir.

      ->RSA
      ->DH
      ->ECC
      ->Kyber
   

->Manuel (Kütüphanesiz) AES-128: AES algoritmasının S-Box, Key Expansion, SubBytes, ShiftRows, MixColumns ve AddRoundKey adımları hazır kütüphane kullanılmadan sıfırdan kodlanmıştır.(standart kurallara göre)


->Proje Çalıştırma Adımları:

   1.Server olan bilgisayar projeyi başlatır(run.py'den) ve (http://127.0.0.1:5000) adresine girerek uygulamayı açar.
   
   2.Client tarafı sunucu bilgisayardan terminale ipconfig yazarak IPv4 Adresini öğrenir.Client tarafının projeyi başlatmasına gerek yoktur.
      ->Örneğin sunucu bilgisayarda terminale ipconfig yazalım:
      çıktının bir kısmı:

      IPv4 Address. . . . . . . . . . . : 192.168.1.103

      şeklinde ise istemci şu adrese giderek uygulamayı açar:http://192.168.1.103:5000
      NOT:Sunucu ve istemci aynı ağa bağlı olmlılar.

   3.Güvenli veya güvensiz mod seçimini yaparak mesajlaşabilirsiniz.


