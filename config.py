PASSWORD_CONFIG = {
    'min_length': 10,                
    'require_uppercase': True,      
    'require_lowercase': True,      
    'require_digit': True,          
    'require_special_char': True,   
    'special_chars': '!@#$%^&*()-_=+[]{}|;:,.<>?',  
    'min_requirements': 4,          
    'password_history_size': 3,     
}

FORBIDDEN_SUBSTRINGS = {
    'password',
    'pass123',
    'qwerty',
    '123456',
    'abc123',
    'admin123',
    'welcome',
    'letmein',
    'monkey123',
    'dragon',
    'baseball',
    'football',
    'superman',
    'trustno1',
    'iloveyou'
}

LOGIN_CONFIG = {
    'max_attempts': 3,              
    'block_duration': 60,          
}

PASSWORD_ERROR_MESSAGES = {
    'min_length': 'Password must be at least {min_length} characters long.',
    'require_uppercase': 'Password must contain at least one uppercase letter.',
    'require_lowercase': 'Password must contain at least one lowercase letter.',
    'require_digit': 'Password must contain at least one digit.',
    'require_special_char': 'Password must contain at least one special character ({chars}).',
    'min_requirements': 'Password must meet all requirements (uppercase, lowercase, digit, special character).',
    'password_history': 'Password cannot be one of your last {history_size} passwords.',
    'forbidden_substring': 'Password contains a common or easily guessable pattern. Please choose a stronger password.'
}

LOGIN_ERROR_MESSAGES = {
    'max_attempts': 'Too many failed login attempts. Please try again in {minutes} minutes.',
    'invalid_credentials': 'Invalid username or password.',
    'account_blocked': 'Account is temporarily blocked. Please try again in {minutes} minutes.'
}
