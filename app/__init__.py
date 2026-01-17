from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import os

db = SQLAlchemy()
migrate = Migrate()


def create_app():
    app = Flask(__name__, template_folder='../templates', static_folder='../static')

    # Security settings
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'change-me-in-production')
    app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

    # Database
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
        'DATABASE_URL',
        'postgresql://sshmonitor:sshmonitor@localhost:5432/sshmonitor'
    )
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
    }

    # API Key for agents
    app.config['API_KEY'] = os.environ.get('API_KEY', 'change-me-in-production')

    # Dashboard password (optional - if not set, dashboard is public)
    app.config['DASHBOARD_PASSWORD'] = os.environ.get('DASHBOARD_PASSWORD', '')

    # Optional Slack webhook for consolidated alerts
    app.config['SLACK_WEBHOOK'] = os.environ.get('SLACK_WEBHOOK', '')

    db.init_app(app)
    migrate.init_app(app, db)

    from app.routes import main_bp, api_bp
    app.register_blueprint(main_bp)
    app.register_blueprint(api_bp, url_prefix='/api/v1')

    return app
