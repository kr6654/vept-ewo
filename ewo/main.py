from flask import Blueprint, render_template, redirect, url_for, request, flash, jsonify, send_file
from flask_login import login_required, current_user
from datetime import datetime
from io import BytesIO
import pandas as pd
from .models import User, EWO, EWOHistory, WhyWhyAnalysis, OilReport, OilConsumption
from . import db

main = Blueprint('main', __name__)

@main.route('/')
def index():
    return redirect(url_for('auth.login'))

@main.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin_or_administrator():
        return redirect(url_for('auth.login'))
    pending_users = User.query.filter_by(is_approved=False).all()
    return render_template('admin_dashboard.html', pending_users=pending_users)

@main.route('/production/dashboard')
@login_required
def production_dashboard():
    if current_user.role != 'production':
        return redirect(url_for('auth.login'))
    ewos = EWO.query.all()
    return render_template('production_dashboard.html', ewos=ewos)

@main.route('/maintenance/dashboard')
@login_required
def maintenance_dashboard():
    if current_user.role != 'maintenance':
        return redirect(url_for('auth.login'))
    ewos = EWO.query.filter_by(resolved=False).all()
    return render_template('maintenance_dashboard.html', ewos=ewos)

@main.route('/oil-supervisor/dashboard')
@login_required
def oil_supervisor_dashboard():
    if current_user.role != 'oil_supervisor':
        return redirect(url_for('auth.login'))
    reports = OilReport.query.all()
    consumptions = OilConsumption.query.all()
    return render_template('oil_supervisor_dashboard.html', reports=reports, consumptions=consumptions)

# Add the rest of your routes here (create_ewo, resolve_ewo, etc.)
# Make sure to update the template references to use the blueprint name
# For example: url_for('main.production_dashboard') instead of url_for('production_dashboard')
