from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from .models import User
from . import db, login_manager

auth = Blueprint('auth', __name__)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            if not user.is_approved:
                flash('Your account is pending approval')
                return redirect(url_for('auth.login'))

            login_user(user)
            return redirect(get_redirect_target(user.role))
        else:
            flash('Invalid username or password')

    return render_template('login.html')

@auth.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role')
        full_name = request.form.get('full_name')
        employee_code = request.form.get('employee_code')

        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('auth.register'))

        if User.query.filter_by(employee_code=employee_code).first():
            flash('Employee code already exists')
            return redirect(url_for('auth.register'))

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password, role=role,
                    full_name=full_name, employee_code=employee_code)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! Please wait for admin approval.')
        return redirect(url_for('auth.login'))

    return render_template('register.html')

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

def get_redirect_target(role):
    if role == 'production':
        return url_for('main.production_dashboard')
    elif role == 'maintenance':
        return url_for('main.maintenance_dashboard')
    elif role == 'oil_supervisor':
        return url_for('main.oil_supervisor_dashboard')
    else:
        return url_for('main.admin_dashboard')
