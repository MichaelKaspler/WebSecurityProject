import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import os
import re
from config import PASSWORD_CONFIG, PASSWORD_ERROR_MESSAGES

app = Flask(__name__)
app.secret_key = 'your_secret_key'  

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row  
    return conn

def init_db():
    if not os.path.exists('database.db'):
        conn = get_db_connection()
        with open('schema.sql') as f:
            conn.executescript(f.read())
        conn.commit()
        conn.close()
        print("Database initialized successfully")

def validate_password(password):
    """
    Validate password against configuration requirements
    Returns (is_valid, error_message)
    """
    if len(password) < PASSWORD_CONFIG['min_length']:
        return False, PASSWORD_ERROR_MESSAGES['min_length'].format(
            min_length=PASSWORD_CONFIG['min_length']
        )
    
    requirements_met = 0
    requirements_messages = []

    has_uppercase = any(c.isupper() for c in password)
    if has_uppercase:
        requirements_met += 1
    elif PASSWORD_CONFIG['require_uppercase']:
        requirements_messages.append(PASSWORD_ERROR_MESSAGES['require_uppercase'])
    
    # Check for lowercase letter
    has_lowercase = any(c.islower() for c in password)
    if has_lowercase:
        requirements_met += 1
    elif PASSWORD_CONFIG['require_lowercase']:
        requirements_messages.append(PASSWORD_ERROR_MESSAGES['require_lowercase'])
    
    # Check for digit
    has_digit = any(c.isdigit() for c in password)
    if has_digit:
        requirements_met += 1
    elif PASSWORD_CONFIG['require_digit']:
        requirements_messages.append(PASSWORD_ERROR_MESSAGES['require_digit'])
    
    # Check for special character
    special_chars = PASSWORD_CONFIG['special_chars']
    has_special = any(c in special_chars for c in password)
    if has_special:
        requirements_met += 1
    elif PASSWORD_CONFIG['require_special_char']:
        requirements_messages.append(
            PASSWORD_ERROR_MESSAGES['require_special_char'].format(chars=special_chars)
        )
    
    # Check if we meet the minimum number of requirements
    min_requirements = PASSWORD_CONFIG['min_requirements']
    if requirements_met < min_requirements:
        return False, PASSWORD_ERROR_MESSAGES['min_requirements'].format(
            min_requirements=min_requirements
        )
    
    return True, ""

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    user = conn.execute('SELECT username FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    conn.close()
    
    return render_template('home.html', username=user['username'])

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login route"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Input validation
        if not username or not password:
            flash('Username and password are required')
            return render_template('login.html')
        
        # Check if user exists and password is correct
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            # Store user ID in session
            session.clear()
            session['user_id'] = user['id']
            flash('Login successful!')
            return redirect(url_for('index'))
        
        flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Registration route"""
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        # Input validation
        if not username or not email or not password:
            flash('All fields are required')
            return render_template('register.html')
        
        # Validate password
        is_valid, error_message = validate_password(password)
        if not is_valid:
            flash(error_message)
            return render_template('register.html')
        
        # Check if username or email already exists
        conn = get_db_connection()
        existing_user = conn.execute('SELECT id FROM users WHERE username = ? OR email = ?', 
                                    (username, email)).fetchone()
        
        if existing_user:
            conn.close()
            flash('Username or email already exists')
            return render_template('register.html')
        
        # Hash the password for security
        hashed_password = generate_password_hash(password)
        
        # Insert new user into database
        conn.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                    (username, email, hashed_password))
        conn.commit()
        conn.close()
        
        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))
    
    # Pass password requirements to the template
    password_requirements = {
        'min_length': PASSWORD_CONFIG['min_length'],
        'require_uppercase': PASSWORD_CONFIG['require_uppercase'],
        'require_lowercase': PASSWORD_CONFIG['require_lowercase'],
        'require_digit': PASSWORD_CONFIG['require_digit'],
        'require_special_char': PASSWORD_CONFIG['require_special_char'],
        'special_chars': PASSWORD_CONFIG['special_chars']
    }
    
    return render_template('register.html', password_requirements=password_requirements)

@app.route('/logout')
def logout():
    """Logout route"""
    session.clear()
    flash('You have been logged out')
    return redirect(url_for('login'))

def vulnerable_login(username, password):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    # DANGEROUS: Directly formatting user input into SQL!
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()
    return user


def sql_injection_dump_users():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    # The injected payload in the password field
    username = ""
    password = "' OR 1=1 --"
    # Vulnerable query
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    print("Executing query:", query)
    cursor.execute(query)
    users = cursor.fetchall()
    conn.close()
    # Print all users returned by the injection
    for user in users:
        print(dict(user)) 

def sql_injection_attack():
    # This payload will always return True for the password check
    username = ""
    password = "' OR 1=1 --"
    user = vulnerable_login(username, password)
    if user:
        print("SQL Injection succeeded! User data:", user)
    else:
        print("SQL Injection failed.")

if __name__ == '__main__':
    # Initialize the database
    init_db()
    # Run the application on port 5000
    app.run(debug=True, port=5000) 
    sql_injection_dump_users()