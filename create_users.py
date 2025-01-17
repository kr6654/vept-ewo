from app import app, db, User

with app.app_context():
    db.create_all()
    # Create production user
    prod_user = User(username='production', password='prod123', role='production')
    # Create maintenance user
    maint_user = User(username='maintenance', password='maint123', role='maintenance')
    # Create admin user
    admin_user = User(username='admin', password='admin123', role='admin')
    db.session.add_all([prod_user, maint_user, admin_user])
    db.session.commit()
    print("Users created successfully!")
