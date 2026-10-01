import os
from app import create_app

# Set production environment as default for WSGI entrypoint
env_mode = os.environ.get('FLASK_ENV', 'production')
application = create_app(env_mode)
app = application

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
