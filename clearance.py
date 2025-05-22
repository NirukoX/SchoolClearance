from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///clearance_system.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    department = db.Column(db.String(20), nullable=True)
    email = db.Column(db.String(120), nullable=True)
    phone = db.Column(db.String(30), nullable=True)
    address = db.Column(db.String(255), nullable=True)

# Department model
class Department(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)

# Clearance model
class Clearance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    department_id = db.Column(db.Integer, db.ForeignKey('department.id'))
    status = db.Column(db.String(20), default='Pending')
    remarks = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    department = db.relationship('Department', backref='clearances')
    student = db.relationship('User', backref='clearances', foreign_keys=[student_id])  # Add this line

# Notification model
class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    message = db.Column(db.String(255))
    is_read = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class Remark(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    department = db.Column(db.String(100), nullable=False)
    issue = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(50), nullable=False, default='Rejected')
    action = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)

# Course model (for recommendation)
class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255))
    rating = db.Column(db.Float)
    popularity = db.Column(db.Integer, default=0)

# Review model
class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'))
    rating = db.Column(db.Integer)
    comment = db.Column(db.String(255))
    sentiment = db.Column(db.String(20))  # Positive, Negative, Neutral

# --- Officer notification helper ---
def notify_officers(department_name, message):
    officers = User.query.filter_by(role='officer', department=department_name).all()
    for officer in officers:
        notification = Notification(
            user_id=officer.id,
            message=message,
            is_read=False,
            timestamp=datetime.datetime.utcnow()
        )
        db.session.add(notification)
    db.session.commit()

@login_manager.user_loader
def load_user(user_id):
    if not user_id:
        return None
    try:
        return User.query.get(int(user_id))
    except ValueError:
        return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username, password=password).first()
        if user:
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']  # USN
        department = request.form['department']
        # Check for duplicate username or USN
        if User.query.filter_by(username=username).first():
            flash('Username already exists. Please choose another.')
        elif User.query.filter_by(password=password).first():
            flash('USN already exists. Please use a different USN.')
        else:
            new_user = User(username=username, password=password, role='student', department=department)
            db.session.add(new_user)
            db.session.commit()
            # Assign clearances for all departments
            departments = Department.query.all()
            for dept in departments:
                clearance = Clearance(student_id=new_user.id, department_id=dept.id)
                db.session.add(clearance)
            db.session.commit()
            flash('Registration successful')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    elif current_user.role == 'student':
        clearances = Clearance.query.filter_by(student_id=current_user.id).all()
        unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
        return render_template('student_dashboard.html', clearances=clearances, unread_count=unread_count)
    elif current_user.role == 'instructor':
        return render_template('instructor_dashboard.html')
    return 'Access Denied'

@app.route('/clearance_certificate')
@login_required
def clearance_certificate():
    # Example: Set a clearance date for the current user
    if not hasattr(current_user, 'clearance_date'):
        current_user.clearance_date = datetime.datetime.utcnow()
    return render_template('clearance_certificate.html')

@app.route('/request', methods=['GET', 'POST'])
@login_required
def request_page():
    if request.method == 'POST':
        request_message = request.form['request_message']
        # For each department, create a pending clearance if not already present
        departments = Department.query.all()
        for dept in departments:
            clearance = Clearance.query.filter_by(student_id=current_user.id, department_id=dept.id).first()
            if not clearance:
                clearance = Clearance(
                    student_id=current_user.id,
                    department_id=dept.id,
                    status='Pending',
                    remarks=request_message
                )
                db.session.add(clearance)
            else:
                # Optionally update remarks and set to pending again
                clearance.remarks = request_message
                clearance.status = 'Pending'
        db.session.commit()
        # Notify all officers in each department
        for dept in departments:
            notify_officers(dept.name, f"New clearance request submitted by {current_user.username} for {dept.name}.")
        flash('Your clearance request has been submitted and is pending review.')
        return redirect(url_for('request_page'))
    return render_template('request.html')

@app.route('/officer_login', methods=['GET', 'POST'])
def officer_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        officer = User.query.filter_by(username=username, role='officer').first()
        if officer and officer.password == password:
            session['officer'] = {"username": officer.username, "department": officer.department}
            return redirect(url_for('officer_dashboard'))
        flash('Invalid officer credentials')
    return render_template('officer_login.html')

@app.route('/officer_forgot_password', methods=['GET', 'POST'])
def officer_forgot_password():
    if request.method == 'POST':
        username = request.form['username']
        new_password = request.form['new_password']
        # Find the officer by username
        officer = User.query.filter_by(username=username, role='officer').first()
        if officer:
            officer.password = new_password
            db.session.commit()
            flash('Password reset successful. You can now log in with your new password.')
            return redirect(url_for('officer_login'))
        else:
            flash('Officer username not found.')
    return render_template('officer_forgot_password.html')

# Officer Dashboard
@app.route('/officer_dashboard', methods=['GET'])
def officer_dashboard():
    if 'officer' not in session:
        return redirect(url_for('officer_login'))

    officer_department = session['officer']['department']

    # Query the latest clearance for each student in this department
    subquery = db.session.query(
        Clearance.student_id,
        db.func.max(Clearance.timestamp).label('latest_timestamp')
    ).join(User, Clearance.student_id == User.id)\
     .filter(User.department.in_(['CED', 'BED']) if officer_department in ['Library', 'SSG'] else User.department == officer_department)\
     .group_by(Clearance.student_id).subquery()

    clearances = db.session.query(Clearance).join(
        subquery,
        (Clearance.student_id == subquery.c.student_id) &
        (Clearance.timestamp == subquery.c.latest_timestamp)
    ).join(User).all()

    return render_template('officer_dashboard.html', officer=session['officer'], clearances=clearances)

@app.route('/edit_remark/<int:student_id>', methods=['GET', 'POST'])
def edit_remark(student_id):
    if 'officer' not in session:
        return redirect(url_for('officer_login'))
    officer_department = session['officer']['department']
    department = Department.query.filter_by(name=officer_department).first()
    # Always get the latest clearance for this student and department
    clearance = Clearance.query.filter_by(student_id=student_id, department_id=department.id)\
        .order_by(Clearance.timestamp.desc()).first()
    remark = Remark.query.filter_by(student_id=student_id, department=officer_department).first()
    if request.method == 'POST':
        remarks = request.form['remarks']
        status = request.form['status']
        # Update Clearance
        if clearance:
            clearance.remarks = remarks
            clearance.status = status
            clearance.timestamp = datetime.datetime.utcnow()  # update timestamp to reflect change
            notification = Notification(
                user_id=student_id,
                message=f"{officer_department} updated your clearance: {status}",
                is_read=False,
                timestamp=datetime.datetime.utcnow()
            )
            db.session.add(notification)
            notify_officers(officer_department, f"Remark updated for student ID {student_id} in {officer_department}.")
        # Update or create Remark
        if remark:
            remark.issue = remarks
            remark.status = status
            remark.action = f"Updated by {officer_department} officer"
            remark.timestamp = datetime.datetime.utcnow()
        else:
            remark = Remark(
                student_id=student_id,
                department=officer_department,
                issue=remarks,
                status=status,
                action=f"Created by {officer_department} officer"
            )
            db.session.add(remark)
        db.session.commit()
        flash('Remark updated successfully.')
        return redirect(url_for('officer_dashboard'))
    student = User.query.get(student_id)
    return render_template('edit_remark.html', clearance=clearance, student=student)

@app.route('/remove_remark/<int:remark_id>', methods=['POST'])
def remove_remark(remark_id):
    remark = Remark.query.get_or_404(remark_id)
    db.session.delete(remark)
    db.session.commit()
    flash('Remark removed successfully.')
    return redirect(url_for('officer_dashboard'))

@app.route('/officer_logout', methods=['POST'])
def officer_logout():
    session.pop('officer', None)
    return redirect(url_for('officer_login'))

@app.route('/clearance/update/<int:clearance_id>', methods=['POST'])
@login_required
def update_clearance(clearance_id):
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))
    clearance = Clearance.query.get_or_404(clearance_id)
    clearance.status = request.form['status']
    db.session.commit()
    # Create a notification for the student
    notification = Notification(
        user_id=clearance.student_id,
        message=f"Status changed: {clearance.department.name} {clearance.status}",
        timestamp=datetime.datetime.utcnow()
    )
    db.session.add(notification)
    # Notify all officers in the department
    notify_officers(clearance.department.name, f"Clearance for {clearance.student.username} was {clearance.status.lower()} in {clearance.department.name}.")
    db.session.commit()
    flash('Clearance status updated')
    return redirect(url_for('admin_dashboard'))

# Officer Requests
@app.route('/officer_requests', methods=['GET'])
def officer_requests():
    if 'officer' not in session:
        return redirect(url_for('officer_login'))

    officer_department = session['officer']['department']

    if officer_department in ['Library', 'SSG']:
        approved = Clearance.query.join(User).filter(
            (Clearance.status == 'Cleared') &  # <-- FIXED HERE
            (Clearance.department.has(name=officer_department)) &
            (User.department.in_(['CED', 'BED']))
        ).all()
        rejected = Clearance.query.join(User).filter(
            (Clearance.status == 'Rejected') &
            (Clearance.department.has(name=officer_department)) &
            (User.department.in_(['CED', 'BED']))
        ).all()
    else:
        approved = Clearance.query.join(User).filter(
            (Clearance.status == 'Cleared') &  # <-- FIXED HERE
            (Clearance.department.has(name=officer_department)) &
            (User.department == officer_department)
        ).all()
        rejected = Clearance.query.join(User).filter(
            (Clearance.status == 'Rejected') &
            (Clearance.department.has(name=officer_department)) &
            (User.department == officer_department)
        ).all()

    pending = Clearance.query.join(User).filter(
        (Clearance.status == 'Pending') &
        (Clearance.department.has(name=officer_department)) &
        (
            (User.department.in_(['CED', 'BED'])) if officer_department in ['Library', 'SSG']
            else (User.department == officer_department)
        )
    ).all()

    return render_template(
        'officer_requests.html',
        officer=session['officer'],
        pending=pending,
        approved=approved,
        rejected=rejected
    )

@app.route('/officer_request_action/<int:clearance_id>', methods=['POST'])
def officer_request_action(clearance_id):
    if 'officer' not in session:
        return redirect(url_for('officer_login'))
    clearance = Clearance.query.get_or_404(clearance_id)
    action = request.form['action']
    remarks = request.form.get('remarks', '')
    officer_department = session['officer']['department']

    # Update clearance status and remarks
    if action == 'approve':
        clearance.status = 'Cleared'
    elif action == 'reject':
        clearance.status = 'Rejected'
    clearance.remarks = remarks

    # Update or create the corresponding Remark
    remark = Remark.query.filter_by(student_id=clearance.student_id, department=officer_department).first()
    if remark:
        remark.issue = remarks
        remark.status = clearance.status
        remark.action = f"{clearance.status} by {officer_department} officer"
        remark.timestamp = datetime.datetime.utcnow()
    else:
        remark = Remark(
            student_id=clearance.student_id,
            department=officer_department,
            issue=remarks,
            status=clearance.status,
            action=f"{clearance.status} by {officer_department} officer"
        )
        db.session.add(remark)

    # Add a notification for the student
    notification = Notification(
        user_id=clearance.student_id,
        message=f"Your request for {clearance.department.name} was {clearance.status.lower()}.",
        is_read=False,
        timestamp=datetime.datetime.utcnow()
    )
    db.session.add(notification)
    
    # Notify all officers in the department
    notify_officers(officer_department, f"Request for {clearance.student.username} was {clearance.status.lower()} in {officer_department}.")
    db.session.commit()
    return redirect(url_for('officer_requests'))

@app.route('/officer_departments')
def officer_departments():
    if 'officer' not in session:
        return redirect(url_for('officer_login'))
    officer_department = session['officer']['department']
    officer_credentials = {
        "BED": ["BEDDean", "BEDGovernor", "BEDTreasurer"],
        "CED": ["CEDDean", "CEDGovernor", "CEDTreasurer"],
        "Library": ["HeadLibrarian", "AssistantLibrarian", "StudentAssistant"],
        "SSG": ["SSGPresident", "SSGVicePresident", "SSGSecretary"]
    }
    officers = officer_credentials.get(officer_department, [])
    return render_template('officer_departments.html', officers=officers, department=officer_department)

@app.route('/notifications')
@login_required
def notifications():
    notes = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.timestamp.desc()).all()
    # Count unread notifications
    unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
    # Mark all as read
    for note in notes:
        if not note.is_read:
            note.is_read = True
    db.session.commit()
    return render_template('notifications.html', notifications=notes, unread_count=unread_count)

@app.route('/officer_notifications')
def officer_notifications():
    if 'officer' not in session:
        return redirect(url_for('officer_login'))
    officer = User.query.filter_by(username=session['officer']['username'], role='officer').first()
    notes = Notification.query.filter_by(user_id=officer.id).order_by(Notification.timestamp.desc()).all()
    unread_count = Notification.query.filter_by(user_id=officer.id, is_read=False).count()
    for note in notes:
        if not note.is_read:
            note.is_read = True
    db.session.commit()
    return render_template('officer_notifications.html', notifications=notes, unread_count=unread_count)

@app.route('/remarks')
@login_required
def remarks():
    remarks = Remark.query.filter_by(student_id=current_user.id).all()
    return render_template('remarks.html', remarks=remarks)

@app.route('/resubmit_remarks', methods=['POST'])
@login_required
def resubmit_remarks():
    note = request.form['note']
    flash('Your resubmission has been sent.')
    return redirect(url_for('remarks'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        current_user.username = request.form['username']
        current_user.password = request.form['student_id']
        current_user.email = request.form.get('email', '')
        current_user.phone = request.form.get('phone', '')
        current_user.address = request.form.get('address', '')
        db.session.commit()
        flash('Profile updated successfully.')
        return redirect(url_for('profile'))
    return render_template('profile.html', user=current_user)

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            flash('Please enter both username and password.')
            return render_template('admin_login.html')
        
        # Authenticate admin user
        admin = User.query.filter_by(username=username, role='admin').first()
        if admin and admin.password == password:
            session['admin'] = {"username": admin.username}
            return redirect(url_for('admin_dashboard'))
        
        flash('Invalid admin credentials', 'danger')
    return render_template('admin_login.html')

@app.route('/admin_dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    if 'admin' not in session:
        return redirect(url_for('admin_login'))

    # Handle bulk actions
    if request.method == 'POST':
        action = request.form.get('bulk_action')
        selected_ids = request.form.getlist('selected_users')
        if action == 'reset_passwords':
            for user_id in selected_ids:
                user = User.query.get(int(user_id))
                if user:
                    user.password = "2025"
            db.session.commit()
            flash('Selected users\' passwords have been reset to "2025".')
        elif action == 'change_roles':
            new_role = request.form.get('new_role')
            for user_id in selected_ids:
                user = User.query.get(int(user_id))
                if user and new_role:
                    user.role = new_role
            db.session.commit()
            flash('Selected users\' roles have been updated.')

    # Search/filter logic
    search = request.args.get('search', '').strip()
    filter_role = request.args.get('role', 'all')
    query = User.query
    if search:
        query = query.filter((User.username.ilike(f"%{search}%")) | (User.id.ilike(f"%{search}%")))
    if filter_role in ['student', 'officer']:
        query = query.filter_by(role=filter_role)
    users = query.all()
    return render_template('admin_dashboard.html', admin=session['admin'], users=users, search=search, filter_role=filter_role)

@app.route('/admin_edit_user/<int:user_id>', methods=['GET', 'POST'])
def admin_edit_user(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        user.username = request.form['username']
        user.role = request.form['role']
        db.session.commit()
        flash('User updated successfully.')
        return redirect(url_for('admin_dashboard'))
    return render_template('admin_edit_user.html', user=user)

@app.route('/admin_delete_user/<int:user_id>', methods=['POST'])
def admin_delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully.')
    return redirect(url_for('admin_dashboard'))

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Ensure departments exist
        for dept_name in ["CED", "BED", "Library", "SSG"]:
            if not Department.query.filter_by(name=dept_name).first():
                db.session.add(Department(name=dept_name))
        db.session.commit()

        # --- Reset officer passwords on every restart ---
        officer_credentials = {
            "BED": ["BEDDean", "BEDGovernor", "BEDTreasurer"],
            "CED": ["CEDDean", "CEDGovernor", "CEDTreasurer"],
            "Library": ["HeadLibrarian", "AssistantLibrarian", "StudentAssistant"],
            "SSG": ["SSGPresident", "SSGVicePresident", "SSGSecretary"]
        }
        for dept, usernames in officer_credentials.items():
            for username in usernames:
                officer = User.query.filter_by(username=username, role='officer').first()
                if officer:
                    officer.password = "2025"
                else:
                    # Optionally create the officer if not exists
                    officer = User(username=username, password="2025", role='officer', department=dept)
                    db.session.add(officer)
        db.session.commit()

        # --- Ensure default admin exists and password is 2025 ---
        admin = User.query.filter_by(username="admin", role="admin").first()
        if not admin:
            db.session.add(User(username="admin", password="2025", role="admin"))
        else:
            admin.password = "2025"
        db.session.commit()

    app.run(debug=True)