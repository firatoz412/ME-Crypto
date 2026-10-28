import os
from app import create_app, socketio
from app.controller.auth_controller import auth_bp
from dotenv import load_dotenv

load_dotenv()

app = create_app()

# Auth (Giriş/Kayıt) Blueprint'ini uygulamaya kaydet
app.register_blueprint(auth_bp)

if __name__ == '__main__':
    os.makedirs(os.path.join(app.root_path, '..', 'uploads', 'temp'), exist_ok=True)
    os.makedirs(os.path.join(app.root_path, '..', 'downloads'), exist_ok=True)
    
    socketio.run(
        app, 
        host='0.0.0.0', 
        port=5000, 
        debug=True, 
        allow_unsafe_werkzeug=True
    )