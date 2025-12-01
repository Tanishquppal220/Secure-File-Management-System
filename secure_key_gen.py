"""
Run this script once to generate your security keys
"""
from cryptography.fernet import Fernet
import secrets

# Generate SECRET_KEY for general app security
secret_key = secrets.token_urlsafe(32)
print("=" * 60)
print("SECRET_KEY (for session management):")
print(secret_key)
print("=" * 60)

# Generate ENCRYPTION_KEY for file encryption
encryption_key = Fernet.generate_key(). decode()
print("\nENCRYPTION_KEY (for file encryption):")
print(encryption_key)
print("=" * 60)

# Print ready-to-use . env format
print("\n📋 Copy these to your .env file:")
print("=" * 60)
print(f"SECRET_KEY={secret_key}")
print(f"ENCRYPTION_KEY={encryption_key}")
print("=" * 60)
