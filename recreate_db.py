from app import app, db, User, EWO, OilReport, WhyWhyAnalysis, EWOHistory
from datetime import datetime
from werkzeug.security import generate_password_hash

# Drop all tables and recreate them
with app.app_context():
    db.drop_all()
    db.create_all()

    # Create admin user
    admin = User(
        username='Kartik90003649',
        password=generate_password_hash('K@rt!k@2001'),
        full_name='Kartik',
        role='administrator',
        employee_code='ADMIN001',
        is_approved=True,
        is_administrator=True
    )

    db.session.add(admin)
    db.session.commit()

    print("Database recreated successfully!")
    print("Admin user created:")
    print("Username: Kartik90003649")
    print("Password: K@rt!k@2001")
