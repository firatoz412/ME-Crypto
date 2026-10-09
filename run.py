import os
from app import create_app, socketio

app = create_app()

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