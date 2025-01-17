from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
import pandas as pd
from io import BytesIO, StringIO
import os
from config import config

# Initialize extensions
db = SQLAlchemy()
login_manager = LoginManager()

def create_app(config_name='default'):
    app = Flask(__name__)
    app.config.from_object(config[config_name])

    # Initialize extensions with app
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'login'

    with app.app_context():
        from models import User, EWO, EWOHistory, WhyWhyAnalysis, OilReport, OilConsumption
        db.create_all()

        @login_manager.user_loader
        def load_user(user_id):
            return User.query.get(int(user_id))


        from routes import register_routes
        register_routes(app)

    return app

app = create_app(os.getenv('FLASK_ENV', 'default'))

# Enable CORS for all routes
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE')
    return response

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'production', 'maintenance', 'admin', 'oil_supervisor', 'administrator'
    full_name = db.Column(db.String(100), nullable=False)
    employee_code = db.Column(db.String(20), unique=True, nullable=False)
    is_approved = db.Column(db.Boolean, default=False)
    is_administrator = db.Column(db.Boolean, default=False)  # True only for administrator
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def is_admin_or_administrator(self):
        return self.role in ['admin', 'administrator']

class EWO(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    line = db.Column(db.String(100), nullable=False)  # CB or CH
    operation_number = db.Column(db.String(100), nullable=False)
    shift = db.Column(db.String(50), nullable=False)  # A, B, C, A+B, B+C, A+B+C
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
    status = db.Column(db.String(50), default='open')  # open, resolved, verified, rejected
    why_why_analysis = db.relationship('WhyWhyAnalysis', backref='ewo', lazy=True)
    history = db.relationship('EWOHistory', backref='ewo', lazy=True)

class EWOHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ewo_id = db.Column(db.Integer, db.ForeignKey('ewo.id'))
    action = db.Column(db.String(50))  # created, resolved, rejected, verified
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
    shift = db.Column(db.String(10), nullable=False)  # A, B, C
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
    oil_grade = db.Column(db.String(10), nullable=False)  # 32, 46, 68
    quantity_liters = db.Column(db.Float, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        full_name = request.form['full_name']
        role = request.form['role']
        employee_code = request.form['employee_code']
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))
        
        if User.query.filter_by(employee_code=employee_code).first():
            flash('Employee code already exists', 'danger')
            return redirect(url_for('register'))
        
        user = User(
            username=username,
            password=generate_password_hash(password),
            full_name=full_name,
            role=role,
            employee_code=employee_code,
            is_approved=False,
            is_administrator=False
        )
        
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please wait for admin approval.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin_or_administrator():
        flash('You do not have permission to access the admin dashboard.', 'danger')
        return redirect(url_for(get_redirect_target(current_user.role)))
    
    pending_users = User.query.filter_by(is_approved=False).all()
    pending_ewos = EWO.query.filter(
        (EWO.resolved == False) | (EWO.is_approved == False)
    ).order_by(EWO.created_at.desc()).all()
    completed_ewos = EWO.query.filter_by(resolved=True, verified=True).order_by(EWO.resolved_at.desc()).all()
    oil_reports = OilReport.query.order_by(OilReport.date.desc(), OilReport.shift.desc()).all()
    oil_consumption = OilConsumption.query.order_by(OilConsumption.date.desc(), OilConsumption.shift.desc()).all()
    
    return render_template('admin_dashboard.html',
        pending_users=pending_users,
        pending_ewos=pending_ewos,
        completed_ewos=completed_ewos,
        oil_reports=oil_reports,
        oil_consumption=oil_consumption
    )

@app.route('/approve_user/<int:user_id>', methods=['POST'])
@login_required
def approve_user(user_id):
    if not current_user.is_admin_or_administrator():
        flash('You do not have permission to approve users.', 'danger')
        return redirect(url_for(get_redirect_target(current_user.role)))
    
    user = User.query.get_or_404(user_id)
    user.is_approved = True
    db.session.commit()
    
    flash(f'User {user.full_name} has been approved.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/reject_user/<int:user_id>', methods=['POST'])
@login_required
def reject_user(user_id):
    if not current_user.is_admin_or_administrator():
        flash('You do not have permission to reject users.', 'danger')
        return redirect(url_for(get_redirect_target(current_user.role)))
    
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    
    flash(f'User {user.full_name} has been rejected.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/view_ewo/<int:ewo_id>')
@login_required
def view_ewo(ewo_id):
    if not current_user.is_admin_or_administrator():
        flash('You do not have permission to view EWO details.', 'danger')
        return redirect(url_for(get_redirect_target(current_user.role)))
    
    ewo = EWO.query.get_or_404(ewo_id)
    creator = User.query.get(ewo.created_by)
    resolver = User.query.get(ewo.resolved_by) if ewo.resolved_by else None
    verifier = User.query.get(ewo.verified_by) if ewo.verified_by else None
    
    return jsonify({
        'id': ewo.id,
        'line': ewo.line,
        'operation_number': ewo.operation_number,
        'shift': ewo.shift,
        'breakdown_description': ewo.breakdown_description,
        'created_by': creator.full_name if creator else '',
        'created_at': ewo.created_at.strftime('%Y-%m-%d %H:%M:%S'),
        'status': ewo.status,
        'resolved_by': resolver.full_name if resolver else '',
        'resolved_at': ewo.resolved_at.strftime('%Y-%m-%d %H:%M:%S') if ewo.resolved_at else '',
        'resolution_description': ewo.resolution_description or '',
        'verified_by': verifier.full_name if verifier else '',
        'verified_at': ewo.verified_at.strftime('%Y-%m-%d %H:%M:%S') if ewo.verified_at else ''
    })

@app.route('/view_oil_report/<int:report_id>')
@login_required
def view_oil_report(report_id):
    if not current_user.is_admin_or_administrator():
        flash('You do not have permission to view oil reports.', 'danger')
        return redirect(url_for(get_redirect_target(current_user.role)))
    
    report = OilReport.query.get_or_404(report_id)
    creator = User.query.get(report.created_by)
    
    return jsonify({
        'id': report.id,
        'date': report.date.strftime('%Y-%m-%d'),
        'shift': report.shift,
        'created_by_name': creator.full_name if creator else '',
        'grade_32_barrel': report.grade_32_barrel,
        'grade_46_barrel': report.grade_46_barrel,
        'grade_68_barrel': report.grade_68_barrel,
        'grade_32_open': report.grade_32_open,
        'grade_46_open': report.grade_46_open,
        'grade_68_open': report.grade_68_open,
        'grade_32_trolley': report.grade_32_trolley,
        'grade_46_trolley': report.grade_46_trolley,
        'grade_68_trolley': report.grade_68_trolley
    })

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            if not user.is_approved:
                flash('Your account is pending approval.', 'warning')
                return redirect(url_for('login'))
            
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for(get_redirect_target(user.role)))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/production')
@login_required
def production_dashboard():
    if current_user.role != 'production':
        flash('Unauthorized access')
        return redirect(url_for('login'))
    ewos = EWO.query.all()
    return render_template('production_dashboard.html', ewos=ewos)

@app.route('/maintenance')
@login_required
def maintenance_dashboard():
    if current_user.role != 'maintenance':
        flash('Unauthorized access')
        return redirect(url_for('login'))
    ewos = EWO.query.filter(EWO.status.in_(['open', 'rejected'])).all()
    return render_template('maintenance_dashboard.html', ewos=ewos)

@app.route('/oil_supervisor')
@login_required
def oil_supervisor_dashboard():
    if current_user.role != 'oil_supervisor':
        flash('Unauthorized access')
        return redirect(url_for('login'))
    oil_reports = OilReport.query.all()
    oil_consumptions = OilConsumption.query.all()
    return render_template('oil_supervisor_dashboard.html', oil_reports=oil_reports, oil_consumptions=oil_consumptions)

@app.route('/create_ewo', methods=['POST'])
@login_required
def create_ewo():
    if current_user.role != 'production':
        return {'error': 'Unauthorized'}, 403
    
    data = request.form
    new_ewo = EWO(
        line=data['line'],
        operation_number=data['operation_number'],
        shift=data['shift'],
        breakdown_description=data['breakdown_description'],
        created_by=current_user.id
    )
    db.session.add(new_ewo)
    db.session.flush()  # Get the ID before committing
    
    # Add history entry
    history = EWOHistory(
        ewo_id=new_ewo.id,
        action='created',
        description=f"EWO created for {data['line']} line, operation {data['operation_number']}",
        performed_by=current_user.id
    )
    db.session.add(history)
    db.session.commit()
    return redirect(url_for('production_dashboard'))

@app.route('/resolve_ewo/<int:ewo_id>', methods=['POST'])
@login_required
def resolve_ewo(ewo_id):
    if current_user.role != 'maintenance':
        return {'error': 'Unauthorized'}, 403
    
    ewo = EWO.query.get_or_404(ewo_id)
    resolution_desc = request.form['resolution_description']
    ewo.status = 'resolved'
    ewo.resolved = True
    ewo.resolved_by = current_user.id
    ewo.resolved_at = datetime.utcnow()
    ewo.resolution_description = resolution_desc
    
    # Add history entry
    history = EWOHistory(
        ewo_id=ewo.id,
        action='resolved',
        description=f"EWO resolved with description: {resolution_desc}",
        performed_by=current_user.id
    )
    db.session.add(history)
    db.session.commit()
    return redirect(url_for('maintenance_dashboard'))

@app.route('/why_why_analysis/<int:ewo_id>', methods=['GET', 'POST'])
@login_required
def why_why_analysis(ewo_id):
    if not current_user.is_admin_or_administrator():
        flash('You do not have permission to perform Why-Why analysis.', 'danger')
        return redirect(url_for(get_redirect_target(current_user.role)))
    
    ewo = EWO.query.get_or_404(ewo_id)
    why_why = WhyWhyAnalysis.query.filter_by(ewo_id=ewo_id).first()
    
    if request.method == 'POST':
        if why_why is None:
            why_why = WhyWhyAnalysis(
                ewo_id=ewo_id,
                category=request.form['category'],
                why1=request.form['why1'],
                why2=request.form['why2'],
                why3=request.form['why3'],
                why4=request.form['why4'],
                why5=request.form['why5'],
                counter_measures=request.form['counter_measures'],
                target_date=datetime.strptime(request.form['target_date'], '%Y-%m-%d')
            )
            db.session.add(why_why)
        else:
            why_why.category = request.form['category']
            why_why.why1 = request.form['why1']
            why_why.why2 = request.form['why2']
            why_why.why3 = request.form['why3']
            why_why.why4 = request.form['why4']
            why_why.why5 = request.form['why5']
            why_why.counter_measures = request.form['counter_measures']
            why_why.target_date = datetime.strptime(request.form['target_date'], '%Y-%m-%d')
        
        db.session.commit()
        flash('Why-Why analysis has been saved.', 'success')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('why_why_analysis.html', ewo=ewo, why_why=why_why)

@app.route('/verify_ewo/<int:ewo_id>', methods=['POST'])
@login_required
def verify_ewo(ewo_id):
    if current_user.role != 'production':
        return {'error': 'Unauthorized'}, 403
    
    ewo = EWO.query.get_or_404(ewo_id)
    action = request.form.get('action')
    comment = request.form.get('verification_comment')
    
    if action not in ['verify', 'reject']:
        return {'error': 'Invalid action'}, 400
        
    ewo.status = 'verified' if action == 'verify' else 'rejected'
    ewo.verified = True if action == 'verify' else False
    ewo.verified_by = current_user.id
    ewo.verified_at = datetime.utcnow()
    ewo.verification_comment = comment
    
    # Add history entry
    history = EWOHistory(
        ewo_id=ewo.id,
        action=ewo.status,
        description=f"EWO {ewo.status} with comment: {comment}",
        performed_by=current_user.id
    )
    db.session.add(history)
    db.session.commit()
    return redirect(url_for('production_dashboard'))

@app.route('/approve_ewo/<int:ewo_id>', methods=['POST'])
@login_required
def approve_ewo(ewo_id):
    if not current_user.is_admin_or_administrator():
        flash('You do not have permission to approve EWOs.', 'danger')
        return redirect(url_for(get_redirect_target(current_user.role)))
    
    ewo = EWO.query.get_or_404(ewo_id)
    ewo.is_approved = True
    
    # Add history entry
    history = EWOHistory(
        ewo_id=ewo_id,
        action='approved',
        description=f'EWO approved by {current_user.full_name}',
        performed_by=current_user.id
    )
    
    db.session.add(history)
    db.session.commit()
    
    flash('EWO has been approved successfully.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/export_ewo', methods=['POST'])
@login_required
def export_ewo():
    if not current_user.is_admin_or_administrator():
        flash('You do not have permission to export data.', 'danger')
        return redirect(url_for(get_redirect_target(current_user.role)))

    try:
        start_date = datetime.strptime(request.form['start_date'], '%Y-%m-%d')
        end_date = datetime.strptime(request.form['end_date'], '%Y-%m-%d') + timedelta(days=1)
        export_type = request.form['export_type']
        file_format = request.form.get('file_format', 'excel')

        # Query EWOs based on date range and type
        query = EWO.query.filter(
            EWO.created_at.between(start_date, end_date)
        )

        if export_type == 'pending':
            query = query.filter_by(resolved=False)
        elif export_type == 'resolved':
            query = query.filter_by(resolved=True)
        elif export_type == 'verified':
            query = query.filter_by(verified=True)

        ewos = query.all()

        # Create DataFrame
        data = []
        for ewo in ewos:
            creator = User.query.get(ewo.created_by)
            resolver = User.query.get(ewo.resolved_by) if ewo.resolved_by else None
            verifier = User.query.get(ewo.verified_by) if ewo.verified_by else None
            
            why_why = WhyWhyAnalysis.query.filter_by(ewo_id=ewo.id).first()
            
            row = {
                'EWO ID': ewo.id,
                'Line': ewo.line,
                'Operation Number': ewo.operation_number,
                'Shift': ewo.shift,
                'Breakdown Description': ewo.breakdown_description,
                'Created By': creator.full_name if creator else '',
                'Created At': ewo.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                'Status': ewo.status,
                'Resolved By': resolver.full_name if resolver else '',
                'Resolved At': ewo.resolved_at.strftime('%Y-%m-%d %H:%M:%S') if ewo.resolved_at else '',
                'Resolution Description': ewo.resolution_description or '',
                'Verified By': verifier.full_name if verifier else '',
                'Verified At': ewo.verified_at.strftime('%Y-%m-%d %H:%M:%S') if ewo.verified_at else ''
            }
            
            # Add Why-Why Analysis data if available
            if why_why:
                row.update({
                    'Why-Why Category': why_why.category,
                    'Why 1': why_why.why1,
                    'Why 2': why_why.why2,
                    'Why 3': why_why.why3,
                    'Why 4': why_why.why4,
                    'Why 5': why_why.why5,
                    'Counter Measures': why_why.counter_measures,
                    'Target Date': why_why.target_date.strftime('%Y-%m-%d') if why_why.target_date else ''
                })
            
            data.append(row)

        df = pd.DataFrame(data)

        # Create the export file
        if file_format == 'excel':
            output = BytesIO()
            with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
                df.to_excel(writer, sheet_name='EWOs', index=False)
                worksheet = writer.sheets['EWOs']
                for i, col in enumerate(df.columns):
                    worksheet.set_column(i, i, max(len(col) + 2, df[col].astype(str).str.len().max() + 2))
            output.seek(0)
            
            return send_file(
                output,
                mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                as_attachment=True,
                download_name=f'ewo_report_{start_date.strftime("%Y%m%d")}_{end_date.strftime("%Y%m%d")}.xlsx'
            )
        else:  # CSV
            output = BytesIO()
            df.to_csv(output, index=False, encoding='utf-8-sig')
            output.seek(0)
            
            return send_file(
                output,
                mimetype='text/csv',
                as_attachment=True,
                download_name=f'ewo_report_{start_date.strftime("%Y%m%d")}_{end_date.strftime("%Y%m%d")}.csv'
            )

    except Exception as e:
        flash(f'Error exporting data: {str(e)}', 'danger')
        return redirect(url_for('admin_dashboard'))

@app.route('/add_oil_report', methods=['POST'])
@login_required
def add_oil_report():
    if current_user.role != 'oil_supervisor':
        flash('Unauthorized access')
        return redirect(url_for('login'))
    
    data = request.form
    report = OilReport(
        date=datetime.strptime(data['date'], '%Y-%m-%d').date(),
        shift=data['shift'],
        grade_32_barrel=float(data['grade_32_barrel']),
        grade_46_barrel=float(data['grade_46_barrel']),
        grade_68_barrel=float(data['grade_68_barrel']),
        grade_32_open=float(data['grade_32_open']),
        grade_46_open=float(data['grade_46_open']),
        grade_68_open=float(data['grade_68_open']),
        grade_32_trolley=float(data['grade_32_trolley']),
        grade_46_trolley=float(data['grade_46_trolley']),
        grade_68_trolley=float(data['grade_68_trolley']),
        created_by=current_user.id
    )
    db.session.add(report)
    db.session.commit()
    flash('Oil report added successfully')
    return redirect(url_for('oil_supervisor_dashboard'))

@app.route('/add_oil_consumption', methods=['POST'])
@login_required
def add_oil_consumption():
    if current_user.role != 'oil_supervisor':
        flash('Unauthorized access')
        return redirect(url_for('login'))
    
    data = request.form
    consumption = OilConsumption(
        date=datetime.strptime(data['date'], '%Y-%m-%d').date(),
        shift=data['shift'],
        machine_name=data['machine_name'],
        oil_grade=data['oil_grade'],
        quantity_liters=float(data['quantity_liters']),
        created_by=current_user.id
    )
    db.session.add(consumption)
    db.session.commit()
    flash('Oil consumption added successfully')
    return redirect(url_for('oil_supervisor_dashboard'))

@app.route('/export_oil_report', methods=['POST'])
@login_required
def export_oil_report():
    if current_user.role != 'admin' and current_user.role != 'oil_supervisor' and current_user.role != 'administrator':
        flash('Unauthorized access')
        return redirect(url_for('login'))
    
    start_date = request.form.get('start_date')
    end_date = request.form.get('end_date')
    
    if start_date:
        start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
    else:
        start_date = datetime.now().date() - timedelta(days=30)
    
    if end_date:
        end_date = datetime.strptime(end_date, '%Y-%m-%d').date() + timedelta(days=1)
    else:
        end_date = datetime.now().date() + timedelta(days=1)
    
    # Query reports and consumption within date range
    reports = OilReport.query.filter(
        OilReport.date >= start_date,
        OilReport.date < end_date
    ).all()
    
    consumptions = OilConsumption.query.filter(
        OilConsumption.date >= start_date,
        OilConsumption.date < end_date
    ).all()
    
    # Create Excel file with multiple sheets
    output = BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        # Reports sheet
        report_data = []
        for report in reports:
            report_data.append({
                'Date': report.date,
                'Shift': report.shift,
                'Created By': User.query.get(report.created_by).full_name if User.query.get(report.created_by) else '',
                'Grade 32 Barrel': report.grade_32_barrel,
                'Grade 46 Barrel': report.grade_46_barrel,
                'Grade 68 Barrel': report.grade_68_barrel,
                'Grade 32 Open': report.grade_32_open,
                'Grade 46 Open': report.grade_46_open,
                'Grade 68 Open': report.grade_68_open,
                'Grade 32 Trolley': report.grade_32_trolley,
                'Grade 46 Trolley': report.grade_46_trolley,
                'Grade 68 Trolley': report.grade_68_trolley
            })
        
        df_reports = pd.DataFrame(report_data)
        df_reports.to_excel(writer, sheet_name='Oil Reports', index=False)
        
        # Consumption sheet
        consumption_data = []
        for consumption in consumptions:
            consumption_data.append({
                'Date': consumption.date,
                'Shift': consumption.shift,
                'Machine': consumption.machine_name,
                'Oil Grade': consumption.oil_grade,
                'Quantity (L)': consumption.quantity_liters
            })
        
        df_consumption = pd.DataFrame(consumption_data)
        df_consumption.to_excel(writer, sheet_name='Oil Consumption', index=False)
        
        # Auto-adjust columns width
        for sheet in writer.sheets.values():
            for column in sheet.columns:
                max_length = 0
                column = [cell for cell in column]
                for cell in column:
                    try:
                        if len(str(cell.value)) > max_length:
                            max_length = len(cell.value)
                    except:
                        pass
                adjusted_width = (max_length + 2)
                sheet.column_dimensions[column[0].column_letter].width = min(adjusted_width, 50)
    
    output.seek(0)
    
    return send_file(
        output,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name=f'Oil_Report_{start_date.strftime("%Y%m%d")}_to_{(end_date - timedelta(days=1)).strftime("%Y%m%d")}.xlsx'
    )

@app.route('/export_oil_data', methods=['POST'])
@login_required
def export_oil_data():
    if not current_user.is_admin_or_administrator():
        flash('You do not have permission to export oil data.', 'danger')
        return redirect(url_for(get_redirect_target(current_user.role)))
    
    try:
        export_format = request.form.get('format', 'excel')

        # Query all oil reports
        reports = OilReport.query.order_by(OilReport.date.desc(), OilReport.shift.desc()).all()
        
        if not reports:
            flash('No oil reports found.', 'warning')
            return redirect(url_for('admin_dashboard'))
        
        # Create DataFrame
        data = []
        for report in reports:
            creator = User.query.get(report.created_by)
            data.append({
                'Date': report.date.strftime('%Y-%m-%d'),
                'Shift': report.shift,
                'Created By': creator.full_name if creator else '',
                'Grade 32 Barrel': report.grade_32_barrel,
                'Grade 46 Barrel': report.grade_46_barrel,
                'Grade 68 Barrel': report.grade_68_barrel,
                'Grade 32 Open': report.grade_32_open,
                'Grade 46 Open': report.grade_46_open,
                'Grade 68 Open': report.grade_68_open,
                'Grade 32 Trolley': report.grade_32_trolley,
                'Grade 46 Trolley': report.grade_46_trolley,
                'Grade 68 Trolley': report.grade_68_trolley,
                'Added At': report.created_at.strftime('%Y-%m-%d %H:%M:%S')
            })
        
        df = pd.DataFrame(data)
        
        if export_format == 'excel':
            # Create Excel file
            output = BytesIO()
            with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
                df.to_excel(writer, sheet_name='Oil Reports', index=False)
                worksheet = writer.sheets['Oil Reports']
                
                # Auto-adjust columns width
                for idx, col in enumerate(df.columns):
                    series = df[col]
                    max_len = max(
                        series.astype(str).map(len).max(),
                        len(str(series.name))
                    ) + 1
                    worksheet.set_column(idx, idx, max_len)
            
            output.seek(0)
            return send_file(
                output,
                mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                as_attachment=True,
                download_name=f'Oil_Stock_Report.xlsx'
            )
        else:
            # Create CSV file
            output = StringIO()
            df.to_csv(output, index=False)
            output.seek(0)
            return send_file(
                BytesIO(output.getvalue().encode('utf-8')),
                mimetype='text/csv',
                as_attachment=True,
                download_name=f'Oil_Stock_Report.csv'
            )
            
    except Exception as e:
        flash(f'Error exporting oil data: {str(e)}', 'danger')
        return redirect(url_for('admin_dashboard'))

@app.route('/export_oil_consumption', methods=['POST'])
@login_required
def export_oil_consumption():
    if not current_user.is_admin_or_administrator():
        flash('You do not have permission to export oil consumption data.', 'danger')
        return redirect(url_for(get_redirect_target(current_user.role)))
    
    try:
        start_date = datetime.strptime(request.form['start_date'], '%Y-%m-%d')
        end_date = datetime.strptime(request.form['end_date'], '%Y-%m-%d') + timedelta(days=1)
        export_format = request.form.get('format', 'excel')
        
        # Query oil consumption within date range
        consumption = OilConsumption.query.filter(
            OilConsumption.date >= start_date,
            OilConsumption.date < end_date
        ).order_by(OilConsumption.date.desc(), OilConsumption.shift.desc()).all()
        
        if not consumption:
            flash('No oil consumption data found for the selected date range.', 'warning')
            return redirect(url_for('admin_dashboard'))
        
        # Create DataFrame
        data = []
        for item in consumption:
            creator = User.query.get(item.created_by)
            data.append({
                'Date': item.date.strftime('%Y-%m-%d'),
                'Shift': item.shift,
                'Machine': item.machine_name,
                'Oil Grade': item.oil_grade,
                'Quantity (L)': item.quantity_liters,
                'Added By': creator.full_name if creator else '',
                'Added At': item.created_at.strftime('%Y-%m-%d %H:%M:%S')
            })
        
        df = pd.DataFrame(data)
        
        if export_format == 'excel':
            # Create Excel file
            output = BytesIO()
            with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
                df.to_excel(writer, sheet_name='Oil Consumption', index=False)
                worksheet = writer.sheets['Oil Consumption']
                
                # Auto-adjust columns width
                for idx, col in enumerate(df.columns):
                    series = df[col]
                    max_len = max(
                        series.astype(str).map(len).max(),
                        len(str(series.name))
                    ) + 1
                    worksheet.set_column(idx, idx, max_len)
            
            output.seek(0)
            return send_file(
                output,
                mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                as_attachment=True,
                download_name=f'Oil_Consumption_{start_date.strftime("%Y%m%d")}_{end_date.strftime("%Y%m%d")}.xlsx'
            )
        else:
            # Create CSV file
            output = StringIO()
            df.to_csv(output, index=False)
            output.seek(0)
            return send_file(
                BytesIO(output.getvalue().encode('utf-8')),
                mimetype='text/csv',
                as_attachment=True,
                download_name=f'Oil_Consumption_{start_date.strftime("%Y%m%d")}_{end_date.strftime("%Y%m%d")}.csv'
            )
            
    except Exception as e:
        flash(f'Error exporting oil consumption data: {str(e)}', 'danger')
        return redirect(url_for('admin_dashboard'))

@app.route('/api/ewo/<int:ewo_id>')
@login_required
def get_ewo_details(ewo_id):
    if not current_user.is_admin_or_administrator():
        return jsonify({'error': 'Unauthorized access'}), 403
    
    ewo = EWO.query.get_or_404(ewo_id)
    creator = User.query.get(ewo.created_by)
    resolver = User.query.get(ewo.resolved_by) if ewo.resolved_by else None
    verifier = User.query.get(ewo.verified_by) if ewo.verified_by else None
    
    return jsonify({
        'id': ewo.id,
        'line': ewo.line,
        'operation_number': ewo.operation_number,
        'shift': ewo.shift,
        'breakdown_description': ewo.breakdown_description,
        'created_by': creator.full_name if creator else '',
        'created_at': ewo.created_at.strftime('%Y-%m-%d %H:%M:%S'),
        'status': ewo.status,
        'resolved_by': resolver.full_name if resolver else '',
        'resolved_at': ewo.resolved_at.strftime('%Y-%m-%d %H:%M:%S') if ewo.resolved_at else '',
        'resolution_description': ewo.resolution_description or '',
        'verified_by': verifier.full_name if verifier else '',
        'verified_at': ewo.verified_at.strftime('%Y-%m-%d %H:%M:%S') if ewo.verified_at else ''
    })

@app.route('/api/oil_report/<int:report_id>')
@login_required
def get_oil_report_details(report_id):
    if not current_user.is_admin_or_administrator():
        return jsonify({'error': 'Unauthorized access'}), 403
    
    report = OilReport.query.get_or_404(report_id)
    creator = User.query.get(report.created_by)
    
    return jsonify({
        'id': report.id,
        'date': report.date.strftime('%Y-%m-%d'),
        'shift': report.shift,
        'created_by_name': creator.full_name if creator else '',
        'grade_32_barrel': report.grade_32_barrel,
        'grade_46_barrel': report.grade_46_barrel,
        'grade_68_barrel': report.grade_68_barrel,
        'grade_32_open': report.grade_32_open,
        'grade_46_open': report.grade_46_open,
        'grade_68_open': report.grade_68_open,
        'grade_32_trolley': report.grade_32_trolley,
        'grade_46_trolley': report.grade_46_trolley,
        'grade_68_trolley': report.grade_68_trolley
    })

def get_redirect_target(role):
    role_routes = {
        'production': 'production_dashboard',
        'maintenance': 'maintenance_dashboard',
        'oil_supervisor': 'oil_supervisor_dashboard',
        'admin': 'admin_dashboard',
        'administrator': 'admin_dashboard'  
    }
    return role_routes.get(role, 'login')

if __name__ == '__main__':
    app.run(debug=True)
