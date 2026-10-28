import hashlib
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Blueprint, request, jsonify,session
from app.config.database import getDatabase as vt
from mysql.connector import Error

auth_bp = Blueprint('auth_bp', __name__)


def init_db():
    try:
        conn = vt()
        if conn:
            cursor = conn.cursor()
            cursor.execute(
                
                '''
                    CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(100) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    is_online TINYINT DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
                '''  
            )
            cursor.execute('UPDATE users SET is_online = 0')
            conn.commit()
            cursor.close()
            conn.close()
            print("user tablosu oluşturuldu")
    except Exception as e:
        print(f"tablo oluşturuken hata oluştu. {e}")

# Uygulama açılışında tabloyu oluştur
init_db()

def hash_password(password: str) -> str:
    "Şifreyi SHA-256 ile özetler."
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

@auth_bp.route('/api/register', methods=['POST'])
def register():
    data = request.get_json() or {}
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()

    if not username or not password:
        return jsonify({'success': False, 'message': 'Kullanıcı adı ve şifre zorunludur.'}), 400

    if len(username) < 3:
        return jsonify({'success': False, 'message': 'Kullanıcı adı en az 3 karakter olmalıdır.'}), 400

    if len(password) < 4:
        return jsonify({'success': False, 'message': 'Şifre en az 4 karakter olmalıdır.'}), 400

    password_hash = generate_password_hash(password)

    try:
        conn = vt()
        if not conn:
            return jsonify({'success': False, 'message': 'Veritabanı bağlantısı kurulamadı.'}), 500

        cursor = conn.cursor()
        cursor.execute('INSERT INTO users (username, password_hash) VALUES (%s, %s)', (username, password_hash))
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({'success': True, 'message': 'Kayıt başarılı! Giriş yapabilirsiniz.'}), 201
    
    except Error as err:
        if err.errno == 1062:
            return jsonify({'success': False, 'message': 'Bu kullanıcı adı zaten alınmış.'}), 409
        return jsonify({'success': False, 'message': f'Veritabanı hatası: {str(err)}'}), 500
    except Exception as e:
        return jsonify({'success': False, 'message': f'Hata oluştu: {str(e)}'}), 500

@auth_bp.route('/api/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()

    if not username or not password:
        return jsonify({'success': False, 'message': 'Kullanıcı adı ve şifre girilmelidir.'}), 400

    try:
        conn = vt()
        if not conn:
            return jsonify({'success': False, 'message': 'Veritabanı bağlantısı kurulamadı.'}), 500

        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT id, password_hash, is_online FROM users WHERE username = %s', (username,))
        user = cursor.fetchone()

        if not user or not check_password_hash(user['password_hash'], password):
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'message': 'Hatalı kullanıcı adı veya şifre!'}), 401

        if user.get('is_online') == 1:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'message': 'Bu hesap ile zaten aktif bir oturum açılmış!'}), 403
        
        cursor.execute('UPDATE users SET is_online = 1 WHERE username = %s', (username,))
        conn.commit()
        cursor.close()
        conn.close()
        
        session['username'] = username
        session['room'] = data.get('room', 'genel')

        return jsonify({'success': True, 'username': username, 'message': 'Giriş başarılı.'}), 200
            
    except Exception as e:
        return jsonify({'success': False, 'message': f'Hata oluştu: {str(e)}'}), 500
    
    
    
@auth_bp.route("/api/logout",methods=['POST'])   
def logout():
    username = session.get('username')
    
    if username:
        try:
            conn = vt()
            if conn:
                cursor = conn.cursor()
                # Kesin olarak bu kullanıcının is_online durumunu 0 yap
                cursor.execute('UPDATE users SET is_online = 0 WHERE username = %s', (username,))
                conn.commit()
                cursor.close()
                conn.close()
                print(f"[+] Kullanıcı çevrimdışı yapıldı: {username}")
        except Exception as e:
            print(f"Çıkış sırasında DB güncellenemedi: {e}")

    session.clear()
    return jsonify({'success':True,'message':'oturum kapatıldı'}),200


@auth_bp.route('/api/check-session', methods=['GET'])
def check_session():
    if 'username' in session:
        return jsonify({
            'logged_in': True,
            'username': session['username'],
            'room': session.get('room', 'genel')
        }), 200
    else:
        return jsonify({'logged_in': False}), 200


    
    