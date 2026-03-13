
from flask import Flask
from app.utils.db import init_db
from app.routes.auth import auth_bp
from app.routes.files import files_bp
from app.routes.admin import admin_bp
from app.routes.analytics import analytics_bp

def create_app():
    app = Flask(__name__)
    app.secret_key = "amqres_secure_key"

    init_db()

    app.register_blueprint(auth_bp)
    app.register_blueprint(files_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(analytics_bp)

    return app

app = create_app()

if __name__ == "__main__":
    app.run(debug=True)
