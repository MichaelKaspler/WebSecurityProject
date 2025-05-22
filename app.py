import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug import security
import os
import re
import html
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
    
    table_exists = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='customers'").fetchone()
       
    if not table_exists:
        try:
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
    """Intentionally insecure login route for educational purposes"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not username or not password:
            flash('Username and password are required')
            return render_template('login.html')

        conn = get_db_connection()

        # ❌ Insecure: Directly concatenating user input into the SQL query
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"

        try:
            users = conn.execute(query).fetchall()

            if users:
                user = users[0]
                session.clear()
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['email'] = user['email']
                flash(f"Welcome, {user['username']}!")
                conn.close()
                return redirect(url_for('index'))
            else:
                flash("Invalid username or password.")
        except sqlite3.Error as e:
            flash(f"Database error: {str(e)}")
        finally:
            conn.close()

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Naively vulnerable registration route"""
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        # Basic input validation
        if not username or not email or not password:
            flash('All fields are required')
            return render_template('register.html')
        
        is_valid, error_message = validate_password(password)
        if not is_valid:
            flash(error_message)
            return render_template('register.html')

        conn = get_db_connection()
        
        try:
            # Naively vulnerable: Direct string concatenation in SQL query
            # Using UNION to bypass UNIQUE constraint
            insert_query = "INSERT INTO users (username, email, password) SELECT '" + username + "', '" + email + "', '" + password + "' WHERE NOT EXISTS (SELECT 1 FROM users WHERE username = '" + username + "')"
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
    """Logout route"""
    session.clear()
    flash('You have been logged out')
    return redirect(url_for('login'))


@app.route('/customers')
def customers():
    """View customers page"""
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
    """Add a new customer"""
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
            # Create and execute query to insert new customer
            query = "INSERT INTO customers (name, user_id) VALUES ('" + customer_name + "', " + str(session['user_id']) + ")"
            conn.execute(query)
            conn.commit()
            
            # Get the customer we just added
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
    """View a specific customer"""
    if 'user_id' not in session:
        flash('You must be logged in to view customers')
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    # Vulnerable to IDOR - intentionally removed user_id check
    # This allows viewing any customer in the database as long as you know the ID
    customer = conn.execute(f"SELECT * FROM customers WHERE id = {customer_id}").fetchone()
    conn.close()
    
    if not customer:
        flash('Customer not found')
        return redirect(url_for('add_customer'))
    
    # Convert row object to dictionary for the template
    customer_dict = dict(customer)
    
    # Deliberately NOT encoding HTML - makes it vulnerable to XSS
    # Removed the html_encode call to allow script injection
    
    return render_template('view_customer.html', customer=customer_dict)

@app.route('/clear_customers', methods=['POST'])
def clear_customers():
    """Delete all customers for the current user"""
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
    """Show confirmation page before deleting all customers"""
    if 'user_id' not in session:
        flash('You must be logged in to delete customers')
        return redirect(url_for('login'))
    
    return render_template('clear_customers.html')

if __name__ == '__main__':
    init_db()
    
    app.run(debug=True, port=5000)