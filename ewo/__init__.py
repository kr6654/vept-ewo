from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from config import config

# Initialize extensions
db = SQLAlchemy()
login_manager = LoginManager()

def create_app(config_name='default'):
    app = Flask(__name__.split('.')[0])
    app.config.from_object(config[config_name])

    # Initialize extensions with app
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'

    with app.app_context():
        # Import models to ensure they are registered
        from .models import User, EWO, EWOHistory, WhyWhyAnalysis, OilReport, OilConsumption
        db.create_all()

        # Register blueprints
        from .auth import auth as auth_blueprint
        app.register_blueprint(auth_blueprint)

        from .main import main as main_blueprint
        app.register_blueprint(main_blueprint)

        return app
