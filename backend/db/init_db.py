from pathlib import Path

from backend.app import create_app
from backend.config import Config
from backend.extensions import db
import backend.models  # noqa: F401


def _resolve_sqlite_path(database_uri: str, instance_path: str) -> Path | None:
    if not database_uri.startswith("sqlite:///"):
        return None

    relative_path = database_uri.removeprefix("sqlite:///")
    if not relative_path or relative_path == ":memory:":
        return None

    db_path = Path(relative_path)
    if not db_path.is_absolute():
        db_path = Path(instance_path) / db_path

    return db_path


def init_db(config_class=Config) -> None:
    app = create_app(config_class)
    db_path = _resolve_sqlite_path(
        app.config["SQLALCHEMY_DATABASE_URI"],
        app.instance_path,
    )
    if db_path is not None:
        db_path.parent.mkdir(parents=True, exist_ok=True)

    with app.app_context():
        db.create_all()
        from backend.models import User
        if User.query.count() == 0 and app.config.get("ADMIN_PASSWORD"):
            admin = User(username=app.config.get("ADMIN_USERNAME") or "admin", role="admin")
            admin.set_password(app.config["ADMIN_PASSWORD"])
            db.session.add(admin)
            db.session.commit()


if __name__ == "__main__":
    init_db()
