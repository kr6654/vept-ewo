from flask import render_template, request, redirect, url_for, flash, jsonify, send_file
from flask_login import login_required, current_user
from models import User, EWO, EWOHistory, WhyWhyAnalysis, OilReport, OilConsumption
from app import db
import pandas as pd
from datetime import datetime
from io import BytesIO

def register_routes(app):
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

    @app.route('/ewo/create', methods=['GET', 'POST'])
    @login_required
    def create_ewo():
        if request.method == 'POST':
            ewo = EWO(
                line=request.form['line'],
                operation_number=request.form['operation_number'],
                shift=request.form['shift'],
                breakdown_description=request.form['breakdown_description'],
                created_by=current_user.id
            )
            db.session.add(ewo)
            db.session.commit()
            
            history = EWOHistory(
                ewo_id=ewo.id,
                action='created',
                description='EWO created',
                performed_by=current_user.id
            )
            db.session.add(history)
            db.session.commit()
            
            flash('EWO created successfully')
            return redirect(url_for('production_dashboard'))
            
        return render_template('create_ewo.html')

    @app.route('/ewo/<int:ewo_id>/resolve', methods=['POST'])
    @login_required
    def resolve_ewo(ewo_id):
        ewo = EWO.query.get_or_404(ewo_id)
        ewo.resolved = True
        ewo.resolved_by = current_user.id
        ewo.resolved_at = datetime.utcnow()
        ewo.resolution_description = request.form['resolution_description']
        ewo.status = 'resolved'
        
        history = EWOHistory(
            ewo_id=ewo.id,
            action='resolved',
            description=f'EWO resolved: {request.form["resolution_description"]}',
            performed_by=current_user.id
        )
        
        db.session.add(history)
        db.session.commit()
        
        flash('EWO resolved successfully')
        return redirect(url_for('maintenance_dashboard'))

    @app.route('/ewo/<int:ewo_id>/verify', methods=['POST'])
    @login_required
    def verify_ewo(ewo_id):
        if not current_user.is_admin_or_administrator():
            return redirect(url_for('login'))
            
        ewo = EWO.query.get_or_404(ewo_id)
        ewo.verified = True
        ewo.verified_by = current_user.id
        ewo.verified_at = datetime.utcnow()
        ewo.status = 'verified'
        
        history = EWOHistory(
            ewo_id=ewo.id,
            action='verified',
            description='EWO verified',
            performed_by=current_user.id
        )
        
        db.session.add(history)
        db.session.commit()
        
        flash('EWO verified successfully')
        return redirect(url_for('admin_dashboard'))

    @app.route('/ewo/<int:ewo_id>/why-why-analysis', methods=['GET', 'POST'])
    @login_required
    def why_why_analysis(ewo_id):
        ewo = EWO.query.get_or_404(ewo_id)
        
        if request.method == 'POST':
            analysis = WhyWhyAnalysis(
                ewo_id=ewo_id,
                category=request.form['category'],
                why1=request.form['why1'],
                why2=request.form['why2'],
                why3=request.form['why3'],
                why4=request.form['why4'],
                why5=request.form['why5'],
                counter_measures=request.form['counter_measures'],
                target_date=datetime.strptime(request.form['target_date'], '%Y-%m-%d').date(),
                created_by=current_user.id
            )
            
            db.session.add(analysis)
            
            history = EWOHistory(
                ewo_id=ewo_id,
                action='why-why-analysis',
                description='Why-Why Analysis completed',
                performed_by=current_user.id
            )
            
            db.session.add(history)
            db.session.commit()
            
            flash('Why-Why Analysis completed successfully')
            return redirect(url_for('view_ewo', ewo_id=ewo_id))
            
        existing_analysis = WhyWhyAnalysis.query.filter_by(ewo_id=ewo_id).first()
        return render_template('why_why_analysis.html', ewo=ewo, analysis=existing_analysis)

    @app.route('/oil-report/add', methods=['GET', 'POST'])
    @login_required
    def add_oil_report():
        if current_user.role != 'oil_supervisor':
            return redirect(url_for('login'))
            
        if request.method == 'POST':
            report = OilReport(
                date=datetime.strptime(request.form['date'], '%Y-%m-%d').date(),
                shift=request.form['shift'],
                grade_32_barrel=float(request.form['grade_32_barrel']),
                grade_46_barrel=float(request.form['grade_46_barrel']),
                grade_68_barrel=float(request.form['grade_68_barrel']),
                grade_32_open=float(request.form['grade_32_open']),
                grade_46_open=float(request.form['grade_46_open']),
                grade_68_open=float(request.form['grade_68_open']),
                grade_32_trolley=float(request.form['grade_32_trolley']),
                grade_46_trolley=float(request.form['grade_46_trolley']),
                grade_68_trolley=float(request.form['grade_68_trolley']),
                created_by=current_user.id
            )
            
            db.session.add(report)
            db.session.commit()
            
            flash('Oil report added successfully')
            return redirect(url_for('oil_supervisor_dashboard'))
            
        return render_template('add_oil_report.html')

    @app.route('/oil-consumption/add', methods=['GET', 'POST'])
    @login_required
    def add_oil_consumption():
        if current_user.role != 'oil_supervisor':
            return redirect(url_for('login'))
            
        if request.method == 'POST':
            consumption = OilConsumption(
                date=datetime.strptime(request.form['date'], '%Y-%m-%d').date(),
                shift=request.form['shift'],
                machine_name=request.form['machine_name'],
                oil_grade=request.form['oil_grade'],
                quantity_liters=float(request.form['quantity_liters']),
                created_by=current_user.id
            )
            
            db.session.add(consumption)
            db.session.commit()
            
            flash('Oil consumption record added successfully')
            return redirect(url_for('oil_supervisor_dashboard'))
            
        return render_template('add_oil_consumption.html')

    @app.route('/export/ewo')
    @login_required
    def export_ewo():
        if not current_user.is_admin_or_administrator():
            return redirect(url_for('login'))
            
        ewos = EWO.query.all()
        data = []
        
        for ewo in ewos:
            creator = User.query.get(ewo.created_by)
            resolver = User.query.get(ewo.resolved_by) if ewo.resolved_by else None
            verifier = User.query.get(ewo.verified_by) if ewo.verified_by else None
            
            data.append({
                'ID': ewo.id,
                'Line': ewo.line,
                'Operation Number': ewo.operation_number,
                'Shift': ewo.shift,
                'Breakdown Description': ewo.breakdown_description,
                'Created By': creator.full_name if creator else '',
                'Created At': ewo.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                'Status': ewo.status,
                'Resolved': 'Yes' if ewo.resolved else 'No',
                'Resolved By': resolver.full_name if resolver else '',
                'Resolved At': ewo.resolved_at.strftime('%Y-%m-%d %H:%M:%S') if ewo.resolved_at else '',
                'Resolution Description': ewo.resolution_description or '',
                'Verified': 'Yes' if ewo.verified else 'No',
                'Verified By': verifier.full_name if verifier else '',
                'Verified At': ewo.verified_at.strftime('%Y-%m-%d %H:%M:%S') if ewo.verified_at else ''
            })
            
        df = pd.DataFrame(data)
        output = BytesIO()
        with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
            df.to_excel(writer, sheet_name='EWOs', index=False)
            
        output.seek(0)
        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name=f'ewo_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.xlsx'
        )

    @app.route('/export/oil-report')
    @login_required
    def export_oil_report():
        if not current_user.is_admin_or_administrator():
            return redirect(url_for('login'))
            
        reports = OilReport.query.all()
        data = []
        
        for report in reports:
            creator = User.query.get(report.created_by)
            
            data.append({
                'Date': report.date.strftime('%Y-%m-%d'),
                'Shift': report.shift,
                'Grade 32 Barrel': report.grade_32_barrel,
                'Grade 46 Barrel': report.grade_46_barrel,
                'Grade 68 Barrel': report.grade_68_barrel,
                'Grade 32 Open': report.grade_32_open,
                'Grade 46 Open': report.grade_46_open,
                'Grade 68 Open': report.grade_68_open,
                'Grade 32 Trolley': report.grade_32_trolley,
                'Grade 46 Trolley': report.grade_46_trolley,
                'Grade 68 Trolley': report.grade_68_trolley,
                'Created By': creator.full_name if creator else '',
                'Created At': report.created_at.strftime('%Y-%m-%d %H:%M:%S')
            })
            
        df = pd.DataFrame(data)
        output = BytesIO()
        with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
            df.to_excel(writer, sheet_name='Oil Reports', index=False)
            
        output.seek(0)
        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name=f'oil_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.xlsx'
        )

    return app
