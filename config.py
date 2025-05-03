import os

# Configuration for the application

RSA_PRIVATE_KEY_PATH = os.path.join(os.getcwd(), "secrets", "private_key.pem")
RSA_PUBLIC_KEY_PATH = os.path.join(os.getcwd(), "secrets", "public_key.pem")
TOKEN_EXPIRATION = 3600  # seconds