from flask import Flask, request, jsonify
from auth import generate_token, decode_token, load_rsa_keys, verify_token, is_token_expired

app = Flask(__name__)


@app.route('/generate_token', methods=['POST'])
def generate():
    data = request.get_json()
    user_id = data.get("user_id")
    roles = data.get("roles")

    if not user_id or not roles:
        return jsonify({"error": "user_id and roles are required"}), 400

    token = generate_token(user_id, roles)
    return jsonify({"token": token})


@app.route('/verify_token', methods=['POST'])
def verify():
    data = request.get_json()
    token = data.get("token")

    if not token:
        return jsonify({"error": "Token is required"}), 400

    try:
        header, payload, signature = decode_token(token)
        _, public_key = load_rsa_keys()

        if not verify_token(header, payload, signature, public_key):
            return jsonify({"error": "Invalid signature"}), 403

        if is_token_expired(payload):
            return jsonify({"error": "Token has expired"}), 403

        return jsonify({"valid": True, "user_id": payload["user_id"], "roles": payload["roles"]})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/protected', methods=['GET'])
def protected():
    token = request.headers.get("Authorization")
    if not token:
        return jsonify({"error": "Authorization token required"}), 403

    if token.startswith("Bearer "):
        token = token.split(" ")[1]

    try:
        header, payload, signature = decode_token(token)
        _, public_key = load_rsa_keys()

        if not verify_token(header, payload, signature, public_key):
            return jsonify({"error": "Invalid token signature"}), 403

        if is_token_expired(payload):
            return jsonify({"error": "Token has expired"}), 403

        if "admin" not in payload["roles"]:
            return jsonify({"error": "Insufficient role"}), 403

        return jsonify({"message": "Access granted", "user_id": payload["user_id"], "roles": payload["roles"]})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


if __name__ == "__main__":
    app.run(debug=True)
