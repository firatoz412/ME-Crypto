import hashlib
import sqlite3
import os
from flask import Blueprint, request, jsonify

auth_bp = Blueprint('auth_bp', __name__)
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'kriptogram.db')

def init_db():
    "Kullanıcı veritabanını ve tablosunu başlatır."
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

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

    password_hash = hash_password(password)

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, password_hash))
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'message': 'Kayıt başarılı! Giriş yapabilirsiniz.'}), 201
    except sqlite3.IntegrityError:
        return jsonify({'success': False, 'message': 'Bu kullanıcı adı zaten alınmış.'}), 409
    except Exception as e:
        return jsonify({'success': False, 'message': f'Hata oluştu: {str(e)}'}), 500

@auth_bp.route('/api/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()

    if not username or not password:
        return jsonify({'success': False, 'message': 'Kullanıcı adı ve şifre girilmelidir.'}), 400

    password_hash = hash_password(password)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM users WHERE username = ? AND password_hash = ?', (username, password_hash))
    user = cursor.fetchone()
    conn.close()

    if user:
        return jsonify({'success': True, 'username': username, 'message': 'Giriş başarılı.'}), 200
    else:
        return jsonify({'success': False, 'message': 'Hatalı kullanıcı adı veya şifre!'}), 401