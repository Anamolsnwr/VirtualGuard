from flask import Flask, render_template, request, redirect, session, url_for
import sqlite3
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates")
)
app.secret_key = "supersecretkey"

DATABASE = os.path.join(BASE_DIR, "users.db")


# -----------------------------
# Create Database Automatically
# -----------------------------
def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


init_db()


# -----------------------------
# Home / Login Page (GET)
# -----------------------------
@app.route('/')
def index():
    return render_template('vitalguard.html')


# -----------------------------
# Login (POST)
# -----------------------------
@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    password = request.form['password']

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM users WHERE email = ? AND password = ?",
        (email, password)
    )
    user = cursor.fetchone()
    conn.close()

    if user:
        session['user_id'] = user[0]
        session['user_name'] = user[1]
        return redirect(url_for('dashboard'))
    else:
        return "Invalid email or password."


# -----------------------------
# Register (POST)
# -----------------------------
@app.route('/register', methods=['POST'])
def register():
    name = request.form['name']
    email = request.form['email']
    password = request.form['password']

    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
            (name, email, password)
        )
        conn.commit()
        conn.close()
        return redirect(url_for('index'))

    except sqlite3.IntegrityError:
        return "Email already exists. Please go back and try again."


# -----------------------------
# Dashboard
# -----------------------------
@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        return f"""
        <h1>Welcome {session['user_name']}!</h1>
        <p>Your VitalGuard system is connected.</p>
        <a href='/logout'>Logout</a>
        """
    else:
        return redirect(url_for('index'))


# -----------------------------
# Logout
# -----------------------------
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))
