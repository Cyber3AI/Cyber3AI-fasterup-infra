"""WSGI entrypoint for gunicorn."""
from app import create_app
application = create_app()

if __name__ == '__main__':
    # Dev mode only
    application.run(host='0.0.0.0', port=5000, debug=True)
