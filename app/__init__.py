from flask import Flask
from flask_socketio import SocketIO

socketio = SocketIO(cors_allowed_origins="*", max_http_buffer_size=15 * 1024 * 1024)

def create_app():
    app = Flask(__name__, 
                template_folder='views/templates', 
                static_folder='views/static')
    
    app.config['SECRET_KEY'] = 'secret_key_env_degiskenine_atanacak'

    from app.controller.main_controller import main_bp
    app.register_blueprint(main_bp)


    socketio.init_app(app)

    return app