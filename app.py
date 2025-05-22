import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug import security
import os
import re
import html
import hashlib
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv
from config import PASSWORD_CONFIG, PASSWORD_ERROR_MESSAGES, LOGIN_CONFIG, FORBIDDEN_SUBSTRINGS
import time

app = Flask(__name__)
app.secret_key = 'your_secret_key'  

load_dotenv()

SMTP_SERVER = os.getenv('SMTP_SERVER')
SMTP_PORT = os.getenv('SMTP_PORT')
SMTP_USERNAME = os.getenv('SMTP_USERNAME')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')

def send_reset_email(email, reset_code):
    print(f"SMTP Server: {SMTP_SERVER}")
    print(f"SMTP Port: {SMTP_PORT}")
    print(f"SMTP Username: {SMTP_USERNAME}")
    print(f"SMTP Password: {'*' * len(SMTP_PASSWORD) if SMTP_PASSWORD else 'Not set'}")
    
    msg = MIMEMultipart()
    msg['From'] = SMTP_USERNAME
    msg['To'] = email
    msg['Subject'] = "Password Reset Code"
    
    body = f"""
    Your password reset code is: {reset_code}
    
    Please enter this code to reset your password.
    If you didn't request this, please ignore this email.
    """
    
    msg.attach(MIMEText(body, 'plain'))
    
    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.ehlo() 
        server.starttls()  
        server.ehlo()  
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.send_message(msg)
        server.quit()
        return True
    except smtplib.SMTPAuthenticationError:
        print("SMTP Authentication Error: Please check your email and app password")
        return False
    except smtplib.SMTPException as e:
        print(f"SMTP Error: {str(e)}")
        return False
    except Exception as e:
        print(f"Error sending email: {str(e)}")
        return False

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row  
    return conn

def init_db():
    conn = get_db_connection()
    
    try:
        with open('schema.sql') as f:
            conn.executescript(f.read())
        conn.commit()
        print("Database initialized successfully with full schema")
    except sqlite3.Error as e:
        print(f"Error initializing database: {e}")
    finally:
        conn.close()

init_db()

def validate_password(password):
    if len(password) < PASSWORD_CONFIG['min_length']:
        return False, PASSWORD_ERROR_MESSAGES['min_length'].format(
            min_length=PASSWORD_CONFIG['min_length']
        )
    
    for forbidden in FORBIDDEN_SUBSTRINGS:
        if forbidden.lower() in password.lower():
            return False, PASSWORD_ERROR_MESSAGES['forbidden_substring']
    
    requirements_met = 0
    requirements_messages = []

    has_uppercase = any(c.isupper() for c in password)
    if has_uppercase:
        requirements_met += 1
    elif PASSWORD_CONFIG['require_uppercase']:
        requirements_messages.append(PASSWORD_ERROR_MESSAGES['require_uppercase'])
    
    has_lowercase = any(c.islower() for c in password)
    if has_lowercase:
        requirements_met += 1
    elif PASSWORD_CONFIG['require_lowercase']:
        requirements_messages.append(PASSWORD_ERROR_MESSAGES['require_lowercase'])
   
    has_digit = any(c.isdigit() for c in password)
    if has_digit:
        requirements_met += 1
    elif PASSWORD_CONFIG['require_digit']:
        requirements_messages.append(PASSWORD_ERROR_MESSAGES['require_digit'])
    
    special_chars = PASSWORD_CONFIG['special_chars']
    has_special = any(c in special_chars for c in password)
    if has_special:
        requirements_met += 1
    elif PASSWORD_CONFIG['require_special_char']:
        requirements_messages.append(
            PASSWORD_ERROR_MESSAGES['require_special_char'].format(chars=special_chars)
        )
 
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
    user = conn.execute(f"SELECT username FROM users WHERE id = {session['user_id']}").fetchone()
    conn.close()
    
    return render_template('home.html', username=user['username'])

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not username or not password:
            flash('Username and password are required')
            return render_template('login.html')

        conn = get_db_connection()

        user_check_query = f"SELECT id FROM users WHERE username = '{username}'"
        user = conn.execute(user_check_query).fetchone()

        if user:
            user_id = user['id']
            if 'login_attempts' in session:
                all_attempts = session['login_attempts']
                user_attempts = all_attempts.get(str(user_id), {'count': 0, 'block_time': 0})
                
                if user_attempts['count'] >= LOGIN_CONFIG['max_attempts']:
                    block_time = user_attempts['block_time']
                    current_time = time.time()
                    if current_time - block_time < LOGIN_CONFIG['block_duration']:
                        remaining_time = int(LOGIN_CONFIG['block_duration'] - (current_time - block_time))
                        flash(f'This account is temporarily blocked. Please try again in {remaining_time} seconds.')
                        return render_template('login.html')
                    else:
                        all_attempts[str(user_id)] = {'count': 0, 'block_time': 0}
                        session['login_attempts'] = all_attempts

        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"

        try:
            users = conn.execute(query).fetchall()

            if users:
                user = users[0]
                if 'login_attempts' in session:
                    all_attempts = session['login_attempts']
                    all_attempts[str(user['id'])] = {'count': 0, 'block_time': 0}
                    session['login_attempts'] = all_attempts
                
                session.clear()
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['email'] = user['email']
                flash(f"Welcome, {user['username']}!")
                conn.close()
                return redirect(url_for('index'))
            else:
                if user:  
                    all_attempts = session.get('login_attempts', {})
                    user_attempts = all_attempts.get(str(user_id), {'count': 0, 'block_time': 0})
                    user_attempts['count'] = user_attempts.get('count', 0) + 1
                    
                    if user_attempts['count'] >= LOGIN_CONFIG['max_attempts']:
                        user_attempts['block_time'] = time.time()
                        flash(f'Too many failed attempts. This account is blocked for {LOGIN_CONFIG["block_duration"]} seconds.')
                    else:
                        flash(f"Invalid username or password. {LOGIN_CONFIG['max_attempts'] - user_attempts['count']} attempts remaining.")
                    
                    all_attempts[str(user_id)] = user_attempts
                    session['login_attempts'] = all_attempts
                else:
                    flash("Invalid username or password.")
        except sqlite3.Error as e:
            flash(f"Database error: {str(e)}")
        finally:
            conn.close()

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        if not username or not email or not password:
            flash('All fields are required')
            return render_template('register.html')
        
        is_valid, error_message = validate_password(password)
        if not is_valid:
            flash(error_message)
            return render_template('register.html')

        conn = get_db_connection()
        
        try:
            username_check = f"SELECT username FROM users WHERE username = '{username}'"
            existing_username = conn.execute(username_check).fetchone()
            if existing_username:
                flash('Username already exists')
                return render_template('register.html')
            
            email_check = f"SELECT email FROM users WHERE email = '{email}'"
            existing_email = conn.execute(email_check).fetchone()
            if existing_email:
                flash('Email already exists')
                return render_template('register.html')
            
            insert_query = "INSERT INTO users (username, email, password) VALUES ('" + username + "', '" + email + "', '" + password + "')"
            conn.execute(insert_query)
            conn.commit()
            conn.close()
            
            flash('Registration successful! Please log in.')
            return redirect(url_for('login'))
            
        except sqlite3.Error as e:
            conn.close()
            flash(f'Database error: {str(e)}')
            return render_template('register.html')
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out')
    return redirect(url_for('login'))


@app.route('/customers')
def customers():
    if 'user_id' not in session:
        flash('You must be logged in to view customers')
        return redirect(url_for('login'))
    conn = get_db_connection()
    user_customers = conn.execute(f"SELECT * FROM customers WHERE user_id = {session['user_id']} ORDER BY created_at DESC").fetchall()
    conn.close()

    customers_list = []
    for customer in user_customers:
        customers_list.append(dict(customer))
    
    return render_template('customers.html', customers=customers_list)

def html_encode(text):
    if text is None:
        return ""
    return html.escape(str(text), quote=True)

@app.route('/add_customer', methods=['GET', 'POST'])
def add_customer():
    if 'user_id' not in session:
        flash('You must be logged in to add customers')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        customer_name = request.form['name']
        
        if not customer_name:
            flash('Customer name is required')
            return redirect(url_for('add_customer'))
        
        conn = get_db_connection()
        
        try:
            query = "INSERT INTO customers (name, user_id) VALUES ('" + customer_name + "', " + str(session['user_id']) + ")"
            conn.execute(query)
            conn.commit()
            
            query = "SELECT * FROM customers WHERE name = '" + customer_name + "' ORDER BY id DESC LIMIT 1"
            last_customer = conn.execute(query).fetchone()
            conn.close()
            
            if last_customer:
                customer_id = last_customer['id']
                flash('Customer added successfully!')
                return redirect(url_for('view_customer', customer_id=customer_id))
            else:
                flash('Customer added but could not be retrieved')
                return redirect(url_for('index'))
            
        except sqlite3.Error as e:
            conn.close()
            flash(f'Database error: {str(e)}')
            return redirect(url_for('add_customer'))
    
    return render_template('add_customer.html')

@app.route('/customer/<int:customer_id>')
def view_customer(customer_id):
    if 'user_id' not in session:
        flash('You must be logged in to view customers')
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    customer = conn.execute(f"SELECT * FROM customers WHERE id = {customer_id}").fetchone()
    conn.close()
    
    if not customer:
        flash('Customer not found')
        return redirect(url_for('add_customer'))
    
    customer_dict = dict(customer)
    
    return render_template('view_customer.html', customer=customer_dict)

@app.route('/clear_customers', methods=['POST'])
def clear_customers():
    if 'user_id' not in session:
        flash('You must be logged in to delete customers')
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    try:
        conn.execute("DELETE FROM customers WHERE user_id = ?", (session['user_id'],))
        conn.commit()
        conn.close()
        
        flash('All customers have been deleted')
    except sqlite3.Error as e:
        conn.close()
        flash(f'Error deleting customers: {str(e)}')
    
    return redirect(url_for('add_customer'))

@app.route('/clear_customers_confirm')
def clear_customers_confirm():
    if 'user_id' not in session:
        flash('You must be logged in to delete customers')
        return redirect(url_for('login'))
    
    return render_template('clear_customers.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        
        if not email:
            flash('Email is required')
            return render_template('forgot_password.html')
        
        conn = get_db_connection()
        
        query = f"SELECT * FROM users WHERE email = '{email}'"
        user = conn.execute(query).fetchone()
        
        if user:
            reset_code = hashlib.sha1(str(time.time()).encode()).hexdigest()[:8]
            
            session['reset_code'] = reset_code
            session['reset_email'] = email
            
            if send_reset_email(email, reset_code):
                flash('If a user with that email exists, you will receive a reset code in your email')
            else:
                flash('Error sending reset code. Please try again.')
        else:
            session['reset_code'] = 'dummy_code'
            session['reset_email'] = email
            flash('If a user with that email exists, you will receive a reset code in your email')
        
        conn.close()
        return redirect(url_for('reset_password'))
    
    return render_template('forgot_password.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if 'reset_code' not in session or 'reset_email' not in session:
        flash('Invalid reset request')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        reset_code = request.form['reset_code']
        new_password = request.form['new_password']
        
        if not reset_code or not new_password:
            flash('All fields are required')
            return render_template('reset_password.html')
        
        if reset_code != session['reset_code']:
            flash('Invalid reset code')
            return render_template('reset_password.html')
        
        is_valid, error_message = validate_password(new_password)
        if not is_valid:
            flash(error_message)
            return render_template('reset_password.html')
        
        conn = get_db_connection()
        
        try:
            email = session['reset_email']
            user_query = f"SELECT id, password FROM users WHERE email = '{email}'"
            user = conn.execute(user_query).fetchone()
            
            if not user:
                flash('User not found')
                return render_template('reset_password.html')
            
            if new_password == user['password']:
                flash('New password must be different from your current password')
                return render_template('reset_password.html')
            
            history_query = f"""
                SELECT password FROM password_history 
                WHERE user_id = {user['id']} 
                ORDER BY created_at DESC 
                LIMIT {PASSWORD_CONFIG['password_history_size']}
            """
            history = conn.execute(history_query).fetchall()
            
            for old_password in history:
                if new_password == old_password['password']:
                    flash(f'New password cannot be one of your last {PASSWORD_CONFIG["password_history_size"]} passwords')
                    return render_template('reset_password.html')
            
            update_query = f"UPDATE users SET password = '{new_password}' WHERE email = '{email}'"
            conn.execute(update_query)

            history_insert = f"INSERT INTO password_history (user_id, password) VALUES ({user['id']}, '{user['password']}')"
            conn.execute(history_insert)
            
            conn.commit()
            
            session.pop('reset_code', None)
            session.pop('reset_email', None)
            
            flash('Password has been reset successfully')
            return redirect(url_for('login'))
            
        except sqlite3.Error as e:
            flash(f'Database error: {str(e)}')
        finally:
            conn.close()
    
    return render_template('reset_password.html')

if __name__ == '__main__':
    app.run(debug=True, port=5000)