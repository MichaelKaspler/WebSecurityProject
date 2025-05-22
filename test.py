import hmac
import hashlib

def send_secure_message(message, secret_key):
    hmac_value = hmac.new(
        secret_key.encode('utf-8'),
        message.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    return message, hmac_value

def verify_message(message, received_hmac, secret_key):
    calculated_hmac = hmac.new(
        secret_key.encode('utf-8'),
        message.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(calculated_hmac, received_hmac)

secret_key = "my_secret_key"
original_message = "Transfer $100 to Bob"

message, original_hmac = send_secure_message(original_message, secret_key)

tampered_message = "Transfer $1000 to Eve"

print(f"Original message valid: {verify_message(original_message, original_hmac, secret_key)}")  # True
print(f"Tampered message valid: {verify_message(tampered_message, original_hmac, secret_key)}")  # False