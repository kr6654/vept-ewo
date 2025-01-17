from app import app as application
from app import db

if __name__ == "__main__":
    with application.app_context():
        db.create_all()
    application.run()
