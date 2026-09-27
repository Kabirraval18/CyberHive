from flask import Flask

from backend.config import Config
from backend.extensions import db

from backend.routes.health import health_bp
from backend.routes.api import api_bp
from backend.routes.auth import auth_bp


def create_app(config_class=Config):
    """
    Create and configure the CyberHive Flask application.
    """

    app = Flask(__name__)

    # Load configuration
    app.config.from_object(config_class)
    app.config.setdefault("PERMANENT_SESSION_LIFETIME", config_class.PERMANENT_SESSION_LIFETIME)
    app.config.setdefault("SESSION_REFRESH_EACH_REQUEST", True)

    # Initialize database
    db.init_app(app)

    # Register existing routes
    app.register_blueprint(health_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(auth_bp)

    return app


if __name__ == "__main__":
    app = create_app()

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=app.config["DEBUG"],
        use_reloader=False,
    )