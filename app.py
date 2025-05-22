from flask import Flask, render_template, request, redirect, json, session, jsonify, url_for
import os
from functools import wraps

app = Flask(__name__)
app.secret_key = os.urandom(24)


def login_required(f):
    @wraps(f)
    def decorator_func(*args, **kwargs):
        if 'user' not in session: 
            return redirect(url_for('auth'))
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

@app.route('/auth')
@already_login
def auth():
    return render_template('auth/auth.html')

@app.route('/login', methods = ['POST'])
def login():
    data = request.get_json()
    email = data['email']
    password = data['password']
    
    if email == 'fenillad2103@gmail.com' and password == '123456':
        session['user'] = email
        return jsonify({'success': True, 'redirect_url': '/'}), 200
    else:
        return jsonify({'success': False, 'error' : 'Invalid Credentials'}), 401
    
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth'))

if __name__ == '__main__':
    app.run(debug=True) 