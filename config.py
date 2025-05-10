PASSWORD_CONFIG = {
    'min_length': 10,                
    'require_uppercase': True,      
    'require_lowercase': True,      
    'require_digit': True,          
    'require_special_char': True,   
    'special_chars': '!@#$%^&*()-_=+[]{}|;:,.<>?',  
    'min_requirements': 4,          
}

PASSWORD_ERROR_MESSAGES = {
    'min_length': 'Password must be at least {min_length} characters long.',
    'require_uppercase': 'Password must contain at least one uppercase letter.',
    'require_lowercase': 'Password must contain at least one lowercase letter.',
    'require_digit': 'Password must contain at least one digit.',
    'require_special_char': 'Password must contain at least one special character ({chars}).',
    'min_requirements': 'Password must meet all requirements (uppercase, lowercase, digit, special character).'
}
