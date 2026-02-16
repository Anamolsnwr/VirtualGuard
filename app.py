"""
VitalGuard — app.py  (REAL IoT version + Full Auth)
Register → Login → Session → Dashboard → ESP32 Data → Live UI

Auth endpoints:
  POST /register   → create new account (hashed password)
  POST /login      → authenticate, start Flask session
  GET  /check-auth → check if session is active
  GET  /logout     → clear session
"""
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import random

app = Flask(__name__)
app.secret_key = 'vitalguard_secret_key_2024'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vitalguard.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# ─── Models ────────────────────────────────────────────────────────────────────
class User(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    name       = db.Column(db.String(100), nullable=False, default='User')
    email      = db.Column(db.String(120), unique=True, nullable=True)
    username   = db.Column(db.String(80),  unique=True, nullable=False)
    password   = db.Column(db.String(256), nullable=False)  # Werkzeug hash
    role       = db.Column(db.String(20),  nullable=False, default='patient')
    patient_id = db.Column(db.Integer, db.ForeignKey('patient.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Patient(db.Model):
    id                      = db.Column(db.Integer, primary_key=True)
    name                    = db.Column(db.String(100), nullable=False)
    age                     = db.Column(db.Integer, nullable=False)
    blood_group             = db.Column(db.String(10), nullable=False)
    medical_conditions      = db.Column(db.String(500), nullable=True)
    emergency_contact1_name = db.Column(db.String(100), nullable=True)
    emergency_contact1_phone= db.Column(db.String(20),  nullable=True)
    emergency_contact2_name = db.Column(db.String(100), nullable=True)
    emergency_contact2_phone= db.Column(db.String(20),  nullable=True)

class SensorData(db.Model):
    id               = db.Column(db.Integer, primary_key=True)
    patient_id       = db.Column(db.Integer, db.ForeignKey('patient.id'), nullable=False)
    heart_rate       = db.Column(db.Float, nullable=False)
    spo2             = db.Column(db.Float, nullable=False)
    temperature      = db.Column(db.Float, nullable=False)
    fall_detected    = db.Column(db.Boolean, default=False)
    sos_triggered    = db.Column(db.Boolean, default=False)
    latitude         = db.Column(db.Float, nullable=True)
    longitude        = db.Column(db.Float, nullable=True)
    device_connected = db.Column(db.Boolean, default=True)
    timestamp        = db.Column(db.DateTime, default=datetime.utcnow)

class Alert(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patient.id'), nullable=False)
    alert_type = db.Column(db.String(50), nullable=False)
    message    = db.Column(db.String(500), nullable=False)
    severity   = db.Column(db.String(20), nullable=False)  # 'info' | 'warning' | 'critical'
    is_read    = db.Column(db.Boolean, default=False)
    timestamp  = db.Column(db.DateTime, default=datetime.utcnow)

# ─── Helpers ───────────────────────────────────────────────────────────────────
def get_status(hr, spo2, temp):
    if hr < 50 or hr > 120 or spo2 < 90 or temp > 39.5 or temp < 35: return 'Critical'
    if hr < 60 or hr > 100 or spo2 < 95 or temp > 37.8:               return 'Warning'
    return 'Normal'

def create_alerts(pid, hr, spo2, temp, fall, sos):
    def add(atype, msg, sev):
        db.session.add(Alert(patient_id=pid, alert_type=atype, message=msg, severity=sev))
    if sos:       add('SOS',         'SOS button pressed! Patient needs immediate assistance.', 'critical')
    if fall:      add('Fall',        'Fall detected! Patient may have fallen.', 'critical')
    if hr < 50:   add('HeartRate',   f'Critical: Very low heart rate ({hr:.0f} bpm)', 'critical')
    elif hr > 120:add('HeartRate',   f'Critical: Very high heart rate ({hr:.0f} bpm)', 'critical')
    if spo2 < 90: add('SpO2',        f'Critical: Very low oxygen saturation ({spo2:.1f}%)', 'critical')
    if temp > 39.5:add('Temperature',f'Critical: High fever detected ({temp:.1f}C)', 'critical')
    db.session.commit()

# ─── Auth ──────────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return redirect(url_for('dashboard') if 'user_id' in session else url_for('login'))

# ── POST /register ─────────────────────────────────────────────────────────────
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json(silent=True) or {}
    name     = (data.get('name') or '').strip()
    email    = (data.get('email') or '').strip().lower()
    username = (data.get('username') or email).strip()
    password = data.get('password', '')
    role     = data.get('role', 'patient')

    if not name or not password:
        return jsonify({'status': 'error', 'message': 'Name and password are required'}), 400
    if len(password) < 6:
        return jsonify({'status': 'error', 'message': 'Password must be at least 6 characters'}), 400

    # Check duplicate
    if User.query.filter_by(username=username).first():
        return jsonify({'status': 'user exists', 'message': 'An account with that email already exists'})

    # Create patient record for new user
    patient = Patient(name=name)
    db.session.add(patient)
    db.session.flush()  # get patient.id before commit

    hashed = generate_password_hash(password)
    user   = User(name=name, email=email, username=username,
                  password=hashed, role=role, patient_id=patient.id)
    db.session.add(user)
    db.session.commit()

    return jsonify({'status': 'registered', 'success': True,
                    'message': f'Account created for {name}'})


# ── POST /login ────────────────────────────────────────────────────────────────
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data     = request.get_json(silent=True) or {}
        username = (data.get('username') or '').strip()
        password = data.get('password', '')

        # Look up by username OR email
        user = User.query.filter(
            (User.username == username) | (User.email == username.lower())
        ).first()

        if user and check_password_hash(user.password, password):
            session.update({
                'user_id':    user.id,
                'username':   user.username,
                'name':       user.name,
                'role':       user.role,
                'patient_id': user.patient_id,
            })
            return jsonify({'success': True, 'role': user.role,
                            'username': user.username, 'name': user.name})

        return jsonify({'success': False, 'message': 'Invalid username or password'})
    return render_template('login.html')


# ── GET /check-auth ────────────────────────────────────────────────────────────
@app.route('/check-auth')
def check_auth():
    if 'user_id' in session:
        return jsonify({'logged': True,  'username': session.get('username'),
                        'name':   session.get('name'), 'role': session.get('role')})
    return jsonify({'logged': False})


# ── GET /logout ────────────────────────────────────────────────────────────────
@app.route('/logout')
def logout():
    session.clear()
    # Support both redirect (browser) and JSON (AJAX)
    if request.headers.get('Accept','').find('application/json') >= 0:
        return jsonify({'status': 'logged out'})
    return redirect(url_for('login'))

# ─── Pages ─────────────────────────────────────────────────────────────────────
def require_login():
    return 'user_id' not in session

@app.route('/dashboard')
def dashboard():
    if require_login(): return redirect(url_for('login'))
    return render_template('dashboard.html', username=session.get('username'), role=session.get('role'))

@app.route('/location')
def location():
    if require_login(): return redirect(url_for('login'))
    return render_template('location.html', username=session.get('username'))

@app.route('/alerts-page')
def alerts_page():
    if require_login(): return redirect(url_for('login'))
    return render_template('alerts.html', username=session.get('username'))

@app.route('/profile')
def profile():
    if require_login(): return redirect(url_for('login'))
    patient = Patient.query.get(session.get('patient_id', 1))
    return render_template('profile.html', patient=patient, username=session.get('username'))

# ─── API Endpoints ─────────────────────────────────────────────────────────────
@app.route('/update-data', methods=['POST'])
def update_data():
    """ESP32 sends sensor data to this endpoint."""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    pid  = int(data.get('patient_id', 1))
    hr   = float(data.get('heart_rate', 75))
    spo2 = float(data.get('spo2', 98))
    temp = float(data.get('temperature', 36.5))
    fall = bool(data.get('fall_detected', False))
    sos  = bool(data.get('sos_triggered', False))
    lat  = float(data.get('latitude', 12.9716))
    lng  = float(data.get('longitude', 77.5946))

    db.session.add(SensorData(patient_id=pid, heart_rate=hr, spo2=spo2,
        temperature=temp, fall_detected=fall, sos_triggered=sos,
        latitude=lat, longitude=lng, device_connected=True))
    db.session.commit()
    create_alerts(pid, hr, spo2, temp, fall, sos)

    status = get_status(hr, spo2, temp)
    if fall or sos: status = 'Critical'
    return jsonify({'success': True, 'message': 'Data received', 'status': status})


@app.route('/get-data', methods=['GET'])
def get_data():
    """Website fetches latest sensor data."""
    pid    = int(request.args.get('patient_id', 1))
    latest = SensorData.query.filter_by(patient_id=pid).order_by(SensorData.timestamp.desc()).first()

    if not latest:
        return jsonify({'heart_rate': 75, 'spo2': 98, 'temperature': 36.5,
            'fall_detected': False, 'sos_triggered': False,
            'latitude': 12.9716, 'longitude': 77.5946,
            'device_connected': False, 'status': 'Normal',
            'timestamp': datetime.utcnow().isoformat(), 'unread_alerts': 0})

    unread = Alert.query.filter_by(patient_id=pid, is_read=False).count()
    status = get_status(latest.heart_rate, latest.spo2, latest.temperature)
    if latest.fall_detected or latest.sos_triggered: status = 'Critical'

    return jsonify({
        'heart_rate': latest.heart_rate, 'spo2': latest.spo2,
        'temperature': latest.temperature, 'fall_detected': latest.fall_detected,
        'sos_triggered': latest.sos_triggered, 'latitude': latest.latitude,
        'longitude': latest.longitude, 'device_connected': latest.device_connected,
        'status': status, 'timestamp': latest.timestamp.isoformat(),
        'unread_alerts': unread,
    })


@app.route('/get-alerts', methods=['GET'])
def get_alerts():
    pid = int(request.args.get('patient_id', 1))
    rows = Alert.query.filter_by(patient_id=pid).order_by(Alert.timestamp.desc()).limit(50).all()
    return jsonify([{'id': a.id, 'type': a.alert_type, 'message': a.message,
        'severity': a.severity, 'is_read': a.is_read,
        'timestamp': a.timestamp.isoformat()} for a in rows])


@app.route('/mark-alert-read', methods=['POST'])
def mark_alert_read():
    data  = request.get_json()
    alert = Alert.query.get(data.get('alert_id'))
    if alert:
        alert.is_read = True
        db.session.commit()
    return jsonify({'success': True})


@app.route('/mark-all-read', methods=['POST'])
def mark_all_read():
    data = request.get_json()
    Alert.query.filter_by(patient_id=data.get('patient_id', 1), is_read=False).update({'is_read': True})
    db.session.commit()
    return jsonify({'success': True})


@app.route('/simulate-data', methods=['POST'])
def simulate_data():
    """Demo: simulate ESP32 sensor readings."""
    data     = request.get_json()
    scenario = data.get('scenario', 'normal')
    pid      = session.get('patient_id', 1)
    lat = 12.9716 + random.uniform(-0.005, 0.005)
    lng = 77.5946 + random.uniform(-0.005, 0.005)

    scenarios = {
        'normal':   (random.uniform(65, 85),  random.uniform(97, 99),  random.uniform(36.2, 37.2), False, False),
        'warning':  (random.uniform(100, 110), random.uniform(93, 95),  random.uniform(37.8, 38.5), False, False),
        'critical': (random.uniform(130, 155), random.uniform(85, 89),  random.uniform(39.5, 40.5), False, False),
        'fall':     (random.uniform(80, 95),   random.uniform(95, 98),  random.uniform(36.5, 37.0), True,  False),
        'sos':      (random.uniform(90, 110),  random.uniform(94, 97),  random.uniform(36.5, 37.5), False, True),
    }
    hr, spo2, temp, fall, sos = scenarios.get(scenario, scenarios['normal'])

    db.session.add(SensorData(patient_id=pid,
        heart_rate=round(hr,1), spo2=round(spo2,1), temperature=round(temp,1),
        fall_detected=fall, sos_triggered=sos,
        latitude=round(lat,6), longitude=round(lng,6), device_connected=True))
    db.session.commit()
    create_alerts(pid, hr, spo2, temp, fall, sos)

    return jsonify({'success': True, 'scenario': scenario,
                    'heart_rate': round(hr,1), 'spo2': round(spo2,1), 'temperature': round(temp,1)})


@app.route('/get-history', methods=['GET'])
def get_history():
    pid   = int(request.args.get('patient_id', 1))
    limit = int(request.args.get('limit', 20))
    rows  = SensorData.query.filter_by(patient_id=pid)\
                .order_by(SensorData.timestamp.desc()).limit(limit).all()
    return jsonify([{'heart_rate': r.heart_rate, 'spo2': r.spo2,
        'temperature': r.temperature, 'timestamp': r.timestamp.isoformat()}
        for r in reversed(rows)])


@app.route('/update-profile', methods=['POST'])
def update_profile():
    if require_login(): return jsonify({'success': False}), 401
    data    = request.get_json()
    patient = Patient.query.get(session.get('patient_id', 1))
    if not patient:
        return jsonify({'success': False, 'message': 'Patient not found'})
    mapping = {
        'name': 'name', 'age': 'age', 'blood_group': 'blood_group',
        'medical_conditions': 'medical_conditions',
        'ec1_name': 'emergency_contact1_name', 'ec1_phone': 'emergency_contact1_phone',
        'ec2_name': 'emergency_contact2_name', 'ec2_phone': 'emergency_contact2_phone',
    }
    for json_key, model_attr in mapping.items():
        if json_key in data:
            setattr(patient, model_attr, data[json_key])
    db.session.commit()
    return jsonify({'success': True})

# ─── DB Seed ───────────────────────────────────────────────────────────────────
def init_db():
    with app.app_context():
        db.create_all()
        if not Patient.query.first():
            db.session.add(Patient(name='Rajesh Kumar', age=68, blood_group='B+',
                medical_conditions='Hypertension, Type 2 Diabetes',
                emergency_contact1_name='Priya Kumar (Daughter)',
                emergency_contact1_phone='+91 98765 43210',
                emergency_contact2_name='Dr. Suresh Rao',
                emergency_contact2_phone='+91 80123 45678'))
            db.session.commit()
        if not User.query.first():
            db.session.add_all([
                User(name='Patient Demo',   email='patient@vitalguard.io',
                     username='patient',    password=generate_password_hash('patient123'),
                     role='patient',   patient_id=1),
                User(name='Caretaker Demo', email='caretaker@vitalguard.io',
                     username='caretaker',  password=generate_password_hash('care123'),
                     role='caretaker', patient_id=1),
            ])
            db.session.commit()
            print("  ✅ Demo accounts seeded (passwords hashed with werkzeug)")
        if not SensorData.query.first():
            db.session.add(SensorData(patient_id=1, heart_rate=72, spo2=98.5,
                temperature=36.6, fall_detected=False, sos_triggered=False,
                latitude=12.9716, longitude=77.5946))
            db.session.commit()

if __name__ == '__main__':
    init_db()
    print("\n" + "="*62)
    print("  VitalGuard  –  IoT Healthcare Monitor  🏥")
    print("="*62)
    print("  Dashboard : http://127.0.0.1:5000")
    print("  Register  : POST /register   (create new account)")
    print("  Login     : POST /login      (returns session cookie)")
    print("  Auth check: GET  /check-auth (returns logged:true/false)")
    print()
    print("  Demo logins:")
    print("    patient   / patient123")
    print("    caretaker / care123")
    print()
    print("  ESP32 endpoint:")
    print("    POST http://YOUR_PC_IP:5000/update-data")
    print("="*62 + "\n")
    app.run(debug=True, host='0.0.0.0', port=5000)
