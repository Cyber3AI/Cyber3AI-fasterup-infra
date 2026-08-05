"""FasterUp Portal — Flask application factory with auth."""
import os
import logging
from datetime import timedelta
from logging.handlers import RotatingFileHandler
from flask import Flask
from flask_cors import CORS
from flask_login import LoginManager
from flask_session import Session
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env'))
login_manager = LoginManager()
def create_app():
    app = Flask(__name__,
                static_folder='../static',
                template_folder='../templates')
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-insecure-key')
    app.config['DEBUG'] = os.getenv('DEBUG', 'False').lower() == 'true'
    # === Session configuration ===
    session_hours = int(os.getenv('SESSION_LIFETIME_HOURS', '8'))
    session_dir = '/opt/fasterup-portal/flask_session'
    os.makedirs(session_dir, exist_ok=True)
    app.config['SESSION_TYPE'] = 'filesystem'
    app.config['SESSION_FILE_DIR'] = session_dir
    app.config['SESSION_PERMANENT'] = True
    app.config['SESSION_USE_SIGNER'] = True
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=session_hours)
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['SESSION_COOKIE_SECURE'] = True
    Session(app)
    # === Login manager ===
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.session_protection = 'strong'
    @login_manager.user_loader
    def load_user(user_id):
        from app.services.auth_service import get_user_by_id
        return get_user_by_id(int(user_id))
    @login_manager.unauthorized_handler
    def unauthorized():
        from flask import jsonify, request, redirect, url_for
        if request.path.startswith('/api/'):
            return jsonify({'error': 'authentication_required'}), 401
        return redirect(url_for('auth.login'))
    CORS(app, resources={r"/api/*": {"origins": ["https://192.168.0.22", "https://10.0.0.22", "https://portal.fasterup.local"]}}, supports_credentials=True)
    # === Logging ===
    log_file = os.getenv('LOG_FILE', '/opt/fasterup-portal/logs/portal.log')
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    level = getattr(logging, os.getenv('LOG_LEVEL', 'INFO').upper(), logging.INFO)
    handler = RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=5)
    handler.setFormatter(logging.Formatter(
        '%(asctime)s [%(levelname)s] %(name)s: %(message)s'))
    handler.setLevel(level)
    app.logger.addHandler(handler)
    app.logger.setLevel(level)
    console = logging.StreamHandler()
    console.setFormatter(logging.Formatter('[%(levelname)s] %(message)s'))
    console.setLevel(level)
    app.logger.addHandler(console)
    app.logger.info("FasterUp Portal starting — version 0.2 (auth)")
    # === Register blueprints ===
    from app.routes.api_health import bp as health_bp
    from app.routes.api_wazuh import bp as wazuh_bp
    from app.routes.api_misp import bp as misp_bp
    from app.routes.api_telegram import bp as tg_bp
    from app.routes.api_reports import bp as reports_bp
    from app.routes.api_health_system import bp as health_system_bp
    from app.routes.api_c3scan import bp as c3scan_bp
    from app.routes.auth_routes import bp as auth_bp
    from app.routes.api_dashboard_sso import bp as dashboard_sso_bp
    from app.routes.api_cyber3 import bp as cyber3_bp
    app.register_blueprint(health_bp, url_prefix='/api')
    app.register_blueprint(wazuh_bp, url_prefix='/api')
    app.register_blueprint(misp_bp, url_prefix='/api')
    app.register_blueprint(tg_bp, url_prefix='/api')
    app.register_blueprint(reports_bp, url_prefix='/api')
    app.register_blueprint(health_system_bp, url_prefix='/api')
    app.register_blueprint(c3scan_bp, url_prefix='/api')
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_sso_bp, url_prefix="/api")
    app.register_blueprint(cyber3_bp, url_prefix="/api")
    return app
