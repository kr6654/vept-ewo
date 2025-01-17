from datetime import datetime
from flask_login import UserMixin
from app import db

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
