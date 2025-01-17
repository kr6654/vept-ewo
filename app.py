from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
import pandas as pd
from io import BytesIO
import os

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-do-not-use-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///ewo.db')
if app.config['SQLALCHEMY_DATABASE_URI'].startswith('postgres://'):
    app.config['SQLALCHEMY_DATABASE_URI'] = app.config['SQLALCHEMY_DATABASE_URI'].replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=60)

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    employee_code = db.Column(db.String(20), unique=True, nullable=False)
    is_approved = db.Column(db.Boolean, default=False)
    is_administrator = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def is_admin_or_administrator(self):
        return self.role == 'admin' or self.is_administrator

class EWO(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    line = db.Column(db.String(100), nullable=False)
    operation_number = db.Column(db.String(100), nullable=False)
    shift = db.Column(db.String(50), nullable=False)
    breakdown_description = db.Column(db.Text, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    resolved = db.Column(db.Boolean, default=False)
    resolved_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    resolved_at = db.Column(db.DateTime)
    resolution_description = db.Column(db.Text)
    verified = db.Column(db.Boolean, default=False)
    verified_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    verified_at = db.Column(db.DateTime)
    is_approved = db.Column(db.Boolean, default=False)
    status = db.Column(db.String(50), default='open')
    why_why_analysis = db.relationship('WhyWhyAnalysis', backref='ewo', lazy=True)
    history = db.relationship('EWOHistory', backref='ewo', lazy=True)

class EWOHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ewo_id = db.Column(db.Integer, db.ForeignKey('ewo.id'))
    action = db.Column(db.String(50))
    description = db.Column(db.Text)
    performed_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    performed_at = db.Column(db.DateTime, default=datetime.utcnow)

class WhyWhyAnalysis(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ewo_id = db.Column(db.Integer, db.ForeignKey('ewo.id'), unique=True)
    category = db.Column(db.String(50), nullable=False)
    why1 = db.Column(db.Text, nullable=False)
    why2 = db.Column(db.Text, nullable=False)
    why3 = db.Column(db.Text, nullable=False)
    why4 = db.Column(db.Text, nullable=False)
    why5 = db.Column(db.Text, nullable=False)
    counter_measures = db.Column(db.Text, nullable=False)
    target_date = db.Column(db.Date, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))

class OilReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False)
    shift = db.Column(db.String(10), nullable=False)
    grade_32_barrel = db.Column(db.Float, nullable=False)
    grade_46_barrel = db.Column(db.Float, nullable=False)
    grade_68_barrel = db.Column(db.Float, nullable=False)
    grade_32_open = db.Column(db.Float, nullable=False)
    grade_46_open = db.Column(db.Float, nullable=False)
    grade_68_open = db.Column(db.Float, nullable=False)
    grade_32_trolley = db.Column(db.Float, nullable=False)
    grade_46_trolley = db.Column(db.Float, nullable=False)
    grade_68_trolley = db.Column(db.Float, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class OilConsumption(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False)
    shift = db.Column(db.String(10), nullable=False)
    machine_name = db.Column(db.String(100), nullable=False)
    oil_grade = db.Column(db.String(10), nullable=False)
    quantity_liters = db.Column(db.Float, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role')
        full_name = request.form.get('full_name')
        employee_code = request.form.get('employee_code')

        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))

        if User.query.filter_by(employee_code=employee_code).first():
            flash('Employee code already exists')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password, role=role,
                    full_name=full_name, employee_code=employee_code)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! Please wait for admin approval.')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            if not user.is_approved:
                flash('Your account is pending approval')
                return redirect(url_for('login'))

            login_user(user)
            return redirect(get_redirect_target(user.role))
        else:
            flash('Invalid username or password')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin_or_administrator():
        return redirect(url_for('login'))
    pending_users = User.query.filter_by(is_approved=False).all()
    return render_template('admin_dashboard.html', pending_users=pending_users)

@app.route('/production/dashboard')
@login_required
def production_dashboard():
    if current_user.role != 'production':
        return redirect(url_for('login'))
    ewos = EWO.query.all()
    return render_template('production_dashboard.html', ewos=ewos)

@app.route('/maintenance/dashboard')
@login_required
def maintenance_dashboard():
    if current_user.role != 'maintenance':
        return redirect(url_for('login'))
    ewos = EWO.query.filter_by(resolved=False).all()
    return render_template('maintenance_dashboard.html', ewos=ewos)

@app.route('/oil-supervisor/dashboard')
@login_required
def oil_supervisor_dashboard():
    if current_user.role != 'oil_supervisor':
        return redirect(url_for('login'))
    reports = OilReport.query.all()
    consumptions = OilConsumption.query.all()
    return render_template('oil_supervisor_dashboard.html', reports=reports, consumptions=consumptions)

def get_redirect_target(role):
    if role == 'production':
        return url_for('production_dashboard')
    elif role == 'maintenance':
        return url_for('maintenance_dashboard')
    elif role == 'oil_supervisor':
        return url_for('oil_supervisor_dashboard')
    else:
        return url_for('admin_dashboard')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
