from flask import Flask, render_template, request, redirect, json, session, jsonify, url_for
import os
from functools import wraps
from standard_auth.standard_auth import standard_signup, standard_login, close_db, init_db
# from flask_mail import Mail, Message
from flask_jwt_extended import JWTManager, create_access_token
from datetime import datetime, timezone, timedelta
from flask_jwt_extended import decode_token, get_jwt_identity
import secrets
import sqlite3

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config["JWT_SECRET_KEY"] = os.urandom(24)
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=2)
jwt = JWTManager(app)

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

###############################
#    JWT TOKEN ROUTES STARTS  #
###############################

@app.route('/login_jwt', methods=['POST'])
def login_jwt():
    data = request.get_json()
    email = data.get('emailValue')
    
    if email != 'fenillad2103@gmail.com':
        return jsonify({"msg": "Bad username or password"}), 401
    
    magic_token = secrets.token_urlsafe(32)
    
    # Set token expiry time (e.g., 15 minutes from now)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
    
    # Save token to DB
    conn = sqlite3.connect('magic_link_auth/db/magic_link_auth.db')
    c = conn.cursor()
    c.execute(
        "INSERT INTO magic_tokens (token, email, expires_at) VALUES (?, ?, ?)",
        (magic_token, email, expires_at.isoformat())
    )
    conn.commit()
    conn.close()

    magic_link = f"http://localhost:5000/verify?token={magic_token}"

    return jsonify({"magic_link": magic_link}), 200


@app.route('/verify')
def verify():
    token = request.args.get('token')
    if not token:
        return "Missing token", 400

    conn = sqlite3.connect('magic_link_auth/db/magic_link_auth.db')
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


###############################
#    JWT TOKEN ROUTES ENDS    #
###############################


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