from flask import Flask, render_template, request, redirect, json, session, jsonify, url_for
import os
from functools import wraps
from standard_auth.standard_auth import standard_signup, standard_login, close_db, init_db
# from flask_mail import Mail, Message
# from flask_jwt_extended import JWTManager, create_access_token
from datetime import datetime, timezone, timedelta
# from flask_jwt_extended import decode_token, get_jwt_identity
import secrets
import sqlite3

app = Flask(__name__)
app.secret_key = os.urandom(24)
# app.config["JWT_SECRET_KEY"] = os.urandom(24)
# app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=2)
# jwt = JWTManager(app)

#####################################
# AUTHENTICATION DECORATORS STARTS #
####################################

def login_required(f):
    """
    Decorator to ensure that a user is logged in before accessing the route.
    If the user is not logged in (i.e., 'user' not in session), they are 
    redirected to the login page.
    """
    @wraps(f)
    def decorator_func(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('auth_login'))
        return f(*args, **kwargs)
    return decorator_func


def already_login(f):
    """
    Decorator to prevent logged-in users from accessing routes meant for 
    unauthenticated users (e.g., login or registration pages).
    If the user is already logged in (i.e., 'user' in session), they are 
    redirected to the dashboard page.
    """
    @wraps(f)
    def decorator_func(*args, **kwargs):
        if 'user' in session:
            return redirect(url_for('auth_dashboard'))
        return f(*args, **kwargs)
    return decorator_func

###################################
# AUTHENTICATION DECORATORS ENDS  #
###################################
        
###############################
# STANDARD AUTH ROUTES STARTS #
###############################

# Signup End point
@app.route('/signup', methods=['POST'])
def signup_route():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'success': False, 'error': 'Email and password required'}), 400

    success, message = standard_signup(email, password)  # calling your signup function from standard_auth.py

    if success:
        return jsonify({'success': True, 'message': message}), 201  # Created
    else:
        return jsonify({'success': False, 'error': message}), 409  # Conflict (email exists)


# Login End point
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data['email']
    password = data['password']
    
    success, message = standard_login(email, password)
    if success:
        session['user'] = email
        return jsonify({'success': True, 'redirect_url': '/'}), 200
    else:
        return jsonify({'success': False, 'error': message}), 401

    
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth_login'))

###############################
#  STANDARD AUTH ROUTES ENDS  #
###############################

#####################################
#    MAGIC LINK AUTH ROUTES STARTS  #
####################################

DB_PATH = '../db/magic_link_auth/login_tokens.db'

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS magic_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT UNIQUE NOT NULL,
            email TEXT NOT NULL,
            expires_at TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()


@app.route('/login_magic_link', methods=['POST'])
def login_magic_link():
    try:
        data = request.get_json()

        if not data or 'emailValue' not in data or not data['emailValue'].strip():
            return jsonify({"msg": "Email is required"}), 400

        if data['emailValue'].strip() != "fenillad2103@gmail.com":
            return jsonify({"msg": "Invalid credentials"}), 401

        token = secrets.token_urlsafe(32)
        expires_at = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()

        # Ensure DB and table exist
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO magic_tokens (token, email, expires_at) VALUES (?, ?, ?)",
                (token, data['emailValue'].strip(), expires_at)
            )
            conn.commit()
            conn.close()
        except sqlite3.OperationalError:
            # If DB or table is missing, initialize and retry
            init_db()
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO magic_tokens (token, email, expires_at) VALUES (?, ?, ?)",
                (token, data['emailValue'].strip(), expires_at)
            )
            conn.commit()
            conn.close()

        return jsonify({
            "magic_link": f"http://localhost:5000/verify?token={token}"
        }), 200

    except Exception as e:
        return jsonify({"msg": "Internal server error", "error": str(e)}), 500
    
    
@app.route('/verify')
def verify():
    token = request.args.get('token')
    if not token:
        return "Missing token", 400

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT email, expires_at FROM magic_tokens WHERE token = ?", (token,))
    row = c.fetchone()

    if not row:
        conn.close()
        return "Invalid token", 400

    email, expires_at_str = row
    expires_at = datetime.fromisoformat(expires_at_str).replace(tzinfo=timezone.utc)


    if datetime.now(timezone.utc) > expires_at:
        conn.close()
        return "Token expired", 400

    # Start session
    session['user'] = email

    # Delete token after use
    c.execute("DELETE FROM magic_tokens WHERE token = ?", (token,))
    conn.commit()
    conn.close()
    

    return redirect(url_for('auth_dashboard'))


@app.route('/register_magic_link', methods=['POST'])
def register_magic_link():
    data = request.get_json()
    email = data['email']
    
    # Save the email to DB
    print("Email registered")
    print("Send user email")

#####################################
#    MAGIC LINK AUTH ROUTES ENDS    #
####################################


###############################
#    HTML GET ROUTES STARTS   #
###############################

@app.route('/auth/signup')
def auth_signup():
    return render_template('auth/signup.html')
    

@app.route('/auth/login')
@already_login
def auth_login():
    return render_template('auth/login.html')


@app.route('/')
@login_required
def auth_dashboard():
    return render_template('auth/dashboard.html')

###############################
#    HTML GET ROUTES ENDS     #
###############################

with app.app_context():
    init_db()

if __name__ == '__main__':
    app.run(debug=True) 