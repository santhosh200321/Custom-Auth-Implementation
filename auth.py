import base64
import json
import time
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import config


def load_rsa_keys():
    with open(config.RSA_PRIVATE_KEY_PATH, "rb") as private_file:
        private_key = serialization.load_pem_private_key(private_file.read(), password=None)

    with open(config.RSA_PUBLIC_KEY_PATH, "rb") as public_file:
        public_key = serialization.load_pem_public_key(public_file.read())

    return private_key, public_key


def sign_message(message: str, private_key):
    return private_key.sign(
        message.encode(),
        padding.PKCS1v15(),
        hashes.SHA256()
    )


def verify_signature(message: str, signature: bytes, public_key):
    try:
        public_key.verify(
            signature,
            message.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


def generate_token(user_id, roles):
    header = {
        "alg": "RS256",
        "typ": "JWT-CUSTOM"
    }

    payload = {
        "user_id": user_id,
        "roles": roles,
        "exp": int(time.time()) + config.TOKEN_EXPIRATION
    }

    encoded_header = base64.urlsafe_b64encode(json.dumps(header).encode()).decode()
    encoded_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
    message = f"{encoded_header}.{encoded_payload}"

    private_key, _ = load_rsa_keys()
    signature = sign_message(message, private_key)
    encoded_signature = base64.urlsafe_b64encode(signature).decode()

    return f"{message}.{encoded_signature}"


def decode_token(token):
    try:
        header_b64, payload_b64, signature_b64 = token.split(".")
        header = json.loads(base64.urlsafe_b64decode(header_b64).decode())
        payload = json.loads(base64.urlsafe_b64decode(payload_b64).decode())
        signature = base64.urlsafe_b64decode(signature_b64)

        return header, payload, signature
    except Exception as e:
        raise ValueError("Invalid token format")


def verify_token(header, payload, signature, public_key):
    message = (
        base64.urlsafe_b64encode(json.dumps(header).encode()).decode() +
        "." +
        base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
    )
    return verify_signature(message, signature, public_key)


def is_token_expired(payload):
    return datetime.utcfromtimestamp(payload["exp"]) < datetime.utcnow()
