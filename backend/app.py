from flask import Flask

from backend.config import Config
from backend.extensions import db
from backend.routes.health import health_bp


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    db.init_app(app)
    app.register_blueprint(health_bp)
    return app
