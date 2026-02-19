import os
import sqlite3
from flask import Flask, render_template, request, redirect, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "supersecretkey"

DATABASE = "users.db"


# -----------------------------
# Create Database
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
# Home Page
# -----------------------------
@app.route('/')
def index():
    return render_template('vitalguard.html')


# -----------------------------
# Register
# -----------------------------
@app.route('/register', methods=['POST'])
def register():
    name = request.form['name']
    email = request.form['email']
    password = request.form['password']

    hashed_password = generate_password_hash(password)

    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
            (name, email, hashed_password)
        )
        conn.commit()
        conn.close()

        return "Account created successfully. Please go back and login."

    except sqlite3.IntegrityError:
        return "Email already registered."


# -----------------------------
# Login
# -----------------------------
@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    password = request.form['password']

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()
    conn.close()

    # If user does not exist → reject
    if not user:
        return "No account found. Please register first."

    # If password incorrect → reject
    if not check_password_hash(user[3], password):
        return "Incorrect password."

    # Success
    session['user_id'] = user[0]
    session['user_name'] = user[1]

    return redirect(url_for('dashboard'))


# -----------------------------
# Dashboard
# -----------------------------
@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        return f"""
        <h1>Welcome {session['user_name']}!</h1>
        <p>VitalGuard system active.</p>
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


if __name__ == '__main__':
    app.run(debug=True)
