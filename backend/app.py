from flask import Flask

from backend.config import Config
from backend.extensions import db

from backend.routes.health import health_bp
from backend.routes.api import api_bp


def create_app(config_class=Config):
    """
    Create and configure the CyberHive Flask application.
    """

    app = Flask(__name__)

    # Load configuration
    app.config.from_object(config_class)

    # Initialize database
    db.init_app(app)

    # Register existing routes
    app.register_blueprint(health_bp)
    app.register_blueprint(api_bp)

    return app


if __name__ == "__main__":
    app = create_app()

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=app.config["DEBUG"],
        use_reloader=False,
    )