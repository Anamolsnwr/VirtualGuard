import os
import sqlite3
import datetime
import random
from flask import Flask, render_template, request, redirect, session, url_for, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Load secret key for session management
JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'dev_fallback_secret_key')
DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///users.db')
app.secret_key = os.environ.get('SECRET_KEY', JWT_SECRET_KEY or 'vitalguard_secret_key_2026')

DATABASE = "users.db"


# -----------------------------
# Database Helpers
# -----------------------------
def get_db_connection():
    conn = sqlite3.connect(DATABASE, timeout=20.0)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = sqlite3.connect(DATABASE, timeout=20.0)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout = 5000")
    cursor = conn.cursor()

    # Users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'patient'
        )
    """)

    # Schema migration: ensure 'role' column exists
    cursor.execute("PRAGMA table_info(users)")
    cols = [col[1] for col in cursor.fetchall()]
    if 'role' not in cols:
        cursor.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'patient'")

    # Sensor data table (IoT vitals)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sensor_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER DEFAULT 1,
            heart_rate REAL,
            spo2 REAL,
            temperature REAL,
            fall_detected BOOLEAN,
            sos_triggered BOOLEAN,
            latitude REAL,
            longitude REAL,
            status TEXT DEFAULT 'Normal',
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Seed demo users if empty
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        demo_users = [
            ("Rajesh Kumar", "patient@vitalguard.com", generate_password_hash("patient123"), "patient"),
            ("Caretaker Demo", "caretaker@vitalguard.com", generate_password_hash("care123"), "caretaker")
        ]
        cursor.executemany("INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)", demo_users)

    # Seed initial sensor reading if empty
    cursor.execute("SELECT COUNT(*) FROM sensor_data")
    if cursor.fetchone()[0] == 0:
        cursor.execute("""
            INSERT INTO sensor_data 
            (patient_id, heart_rate, spo2, temperature, fall_detected, sos_triggered, latitude, longitude, status, timestamp)
            VALUES (1, 72.0, 98.5, 36.6, 0, 0, 12.9716, 77.5946, 'Normal', datetime('now'))
        """)

    conn.commit()
    conn.close()


init_db()


# -----------------------------
# CORS & Preflight Handling
# -----------------------------
@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization'
    response.headers['Access-Control-Allow-Methods'] = 'GET,PUT,POST,DELETE,OPTIONS'
    return response


@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        return app.make_default_options_response()


# -----------------------------
# Home Page
# -----------------------------
@app.route('/')
def index():
    return render_template('vitalguard.html')


# -----------------------------
# Auth Check
# -----------------------------
@app.route('/check-auth', methods=['GET'])
def check_auth():
    if 'user_id' in session:
        return jsonify({
            'logged': True,
            'user_id': session.get('user_id'),
            'username': session.get('user_email', session.get('user_name', '')),
            'name': session.get('user_name', ''),
            'role': session.get('user_role', 'patient')
        })
    return jsonify({'logged': False})


# -----------------------------
# Register
# -----------------------------
@app.route('/register', methods=['POST'])
def register():
    if request.is_json:
        data = request.get_json() or {}
        name = data.get('name', '').strip()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        role = data.get('role', 'patient')
    else:
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        role = request.form.get('role', 'patient')

    if not name or not email or not password:
        if request.is_json:
            return jsonify({'status': 'error', 'success': False, 'message': 'All fields are required.'}), 400
        return "All fields are required.", 400

    hashed_password = generate_password_hash(password)

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)",
            (name, email, hashed_password, role)
        )
        conn.commit()
        conn.close()

        if request.is_json:
            return jsonify({
                'status': 'registered',
                'success': True,
                'message': 'Account created successfully.'
            })
        return "Account created successfully. Please go back and login."

    except sqlite3.IntegrityError:
        if request.is_json:
            return jsonify({
                'status': 'user exists',
                'success': False,
                'message': 'An account with that email already exists.'
            }), 409
        return "Email already registered."
    except Exception as e:
        if request.is_json:
            return jsonify({'status': 'error', 'success': False, 'message': str(e)}), 500
        return f"Registration error: {e}"


# -----------------------------
# Login
# -----------------------------
@app.route('/login', methods=['POST'])
def login():
    if request.is_json:
        data = request.get_json() or {}
        identifier = (data.get('username') or data.get('email') or '').strip()
        password = data.get('password', '')
    else:
        identifier = (request.form.get('username') or request.form.get('email') or '').strip()
        password = request.form.get('password', '')

    if not identifier or not password:
        if request.is_json:
            return jsonify({'success': False, 'message': 'Please provide username/email and password.'}), 400
        return "Please provide credentials.", 400

    conn = get_db_connection()
    cursor = conn.cursor()
    # Check email, name, or demo aliases ('patient', 'caretaker')
    cursor.execute("""
        SELECT * FROM users 
        WHERE LOWER(email) = LOWER(?) 
           OR LOWER(name) = LOWER(?)
           OR (LOWER(?) = 'patient' AND LOWER(role) = 'patient')
           OR (LOWER(?) = 'caretaker' AND LOWER(role) = 'caretaker')
        LIMIT 1
    """, (identifier, identifier, identifier, identifier))
    user = cursor.fetchone()
    conn.close()

    # User not found
    if not user:
        if request.is_json:
            return jsonify({'success': False, 'message': 'No account found. Please register first.'}), 404
        return "No account found. Please register first."

    # Incorrect password
    if not check_password_hash(user['password'], password):
        if request.is_json:
            return jsonify({'success': False, 'message': 'Incorrect password.'}), 401
        return "Incorrect password."

    # Successful login
    user_role = user['role'] if 'role' in user.keys() and user['role'] else 'patient'
    session['user_id'] = user['id']
    session['user_name'] = user['name']
    session['user_email'] = user['email']
    session['user_role'] = user_role

    if request.is_json:
        return jsonify({
            'success': True,
            'status': 'success',
            'username': user['email'],
            'name': user['name'],
            'role': user_role
        })

    return redirect(url_for('dashboard'))


# -----------------------------
# Dashboard
# -----------------------------
@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        return redirect(url_for('index'))
    return redirect(url_for('index'))


# -----------------------------
# Logout
# -----------------------------
@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.clear()
    if request.is_json or 'json' in request.headers.get('Accept', '') or request.method == 'POST':
        return jsonify({'success': True, 'message': 'Logged out successfully.'})
    return redirect(url_for('index'))


# -----------------------------
# Get Real / Latest Vitals Data
# -----------------------------
@app.route('/get-data', methods=['GET'])
def get_data():
    patient_id = request.args.get('patient_id', 1)
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM sensor_data 
        WHERE patient_id = ? 
        ORDER BY id DESC LIMIT 1
    """, (patient_id,))
    row = cursor.fetchone()
    conn.close()

    if row:
        return jsonify({
            'heart_rate': row['heart_rate'],
            'spo2': row['spo2'],
            'temperature': row['temperature'],
            'fall_detected': bool(row['fall_detected']),
            'sos_triggered': bool(row['sos_triggered']),
            'latitude': row['latitude'],
            'longitude': row['longitude'],
            'status': row['status'],
            'timestamp': row['timestamp'],
            'device_connected': True
        })
    else:
        return jsonify({
            'heart_rate': 72.0,
            'spo2': 98.5,
            'temperature': 36.6,
            'fall_detected': False,
            'sos_triggered': False,
            'latitude': 12.9716,
            'longitude': 77.5946,
            'status': 'Normal',
            'timestamp': datetime.datetime.now().isoformat(),
            'device_connected': True
        })


# -----------------------------
# Simulate Data Endpoint
# -----------------------------
@app.route('/simulate-data', methods=['POST'])
def simulate_data():
    data = request.get_json() or {}
    scenario = data.get('scenario', 'normal').lower()
    patient_id = data.get('patient_id', 1)

    lat = 12.9716 + random.uniform(-0.005, 0.005)
    lng = 77.5946 + random.uniform(-0.005, 0.005)

    if scenario == 'warning':
        hr = random.uniform(100, 110)
        spo2 = random.uniform(93, 95)
        temp = random.uniform(37.8, 38.5)
        fall, sos, status = False, False, 'Warning'
    elif scenario == 'critical':
        hr = random.uniform(130, 155)
        spo2 = random.uniform(85, 89)
        temp = random.uniform(39.5, 40.5)
        fall, sos, status = False, False, 'Critical'
    elif scenario == 'fall':
        hr = random.uniform(80, 95)
        spo2 = random.uniform(95, 98)
        temp = random.uniform(36.5, 37.0)
        fall, sos, status = True, False, 'Critical'
    elif scenario == 'sos':
        hr = random.uniform(90, 110)
        spo2 = random.uniform(94, 97)
        temp = random.uniform(36.5, 37.5)
        fall, sos, status = False, True, 'Critical'
    else:  # normal
        hr = random.uniform(68, 78)
        spo2 = random.uniform(97, 99)
        temp = random.uniform(36.2, 37.0)
        fall, sos, status = False, False, 'Normal'

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO sensor_data 
        (patient_id, heart_rate, spo2, temperature, fall_detected, sos_triggered, latitude, longitude, status, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
    """, (patient_id, round(hr, 1), round(spo2, 1), round(temp, 1),
          1 if fall else 0, 1 if sos else 0, round(lat, 6), round(lng, 6), status))
    conn.commit()
    conn.close()

    return jsonify({'success': True, 'scenario': scenario})


# -----------------------------
# IoT Hardware Update Endpoint
# -----------------------------
@app.route('/update-data', methods=['POST'])
def update_data():
    if request.is_json:
        data = request.get_json() or {}
    else:
        data = request.form.to_dict()

    patient_id = data.get('patient_id', 1)
    hr = float(data.get('heart_rate') or data.get('hr') or 72.0)
    spo2 = float(data.get('spo2') or 98.0)
    temp = float(data.get('temperature') or data.get('temp') or 36.6)
    fall_raw = data.get('fall_detected', data.get('fall', False))
    fall = (fall_raw is True) or str(fall_raw).lower() in ['true', 'yes', '1']
    sos_raw = data.get('sos_triggered', data.get('sos', False))
    sos = (sos_raw is True) or str(sos_raw).lower() in ['true', 'yes', '1']
    lat = float(data.get('latitude') or data.get('lat') or 12.9716)
    lng = float(data.get('longitude') or data.get('lon') or data.get('lng') or 77.5946)

    if fall or sos or hr < 50 or hr > 120 or spo2 < 90 or temp > 39.5 or temp < 35:
        status = 'Critical'
    elif hr < 60 or hr > 100 or spo2 < 95 or temp > 37.8:
        status = 'Warning'
    else:
        status = 'Normal'

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO sensor_data 
        (patient_id, heart_rate, spo2, temperature, fall_detected, sos_triggered, latitude, longitude, status, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
    """, (patient_id, hr, spo2, temp, 1 if fall else 0, 1 if sos else 0, lat, lng, status))
    conn.commit()
    conn.close()

    return jsonify({'status': 'success', 'message': 'Data updated'})


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    app.run(debug=True, host='0.0.0.0', port=port)
