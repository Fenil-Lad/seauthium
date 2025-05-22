from flask import Flask, render_template, request, redirect, json, session, jsonify, url_for
import os
from functools import wraps
from standard_auth.standard_auth import standard_signup, standard_login, close_db, init_db

app = Flask(__name__)
app.secret_key = os.urandom(24)


def login_required(f):
    @wraps(f)
    def decorator_func(*args, **kwargs):
        if 'user' not in session: 
            return redirect(url_for('auth_login'))
        return f(*args, **kwargs)
    return decorator_func
        

def already_login(f):
    @wraps(f)
    def decorator_func(*args, **kwargs):
        if 'user' in session: 
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorator_func
        

@app.route('/')
@login_required
def home():
    return render_template('home/home.html')


@app.route('/auth/signup')
def auth_signup():
    return render_template('auth/signup.html')
    

@app.route('/auth/login')
@already_login
def auth_login():
    return render_template('auth/login.html')

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


# Run this once to initialize the DB
with app.app_context():
    init_db()

if __name__ == '__main__':
    app.run(debug=True) 