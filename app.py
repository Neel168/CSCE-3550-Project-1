# app.py
from flask import Flask, jsonify, request
import jwt
from keys import get_active_keys, get_key_by_kid
from datetime import datetime, timedelta

app = Flask(__name__)

# Constants for JWT
JWT_ISSUER = "jwks-server"
JWT_AUDIENCE = "test-audience"
JWT_EXPIRATION = timedelta(minutes=30)


@app.route("/.well-known/jwks.json", methods=["GET"])
def jwks():
    """Serve active JWKS."""
    return jsonify({"keys": get_active_keys()}), 200


@app.route("/auth", methods=["POST"])
def auth():
    """Issue a JWT signed with an active or expired key based on query parameter."""
    expired = request.args.get("expired")
    kid = (
        "expired_key" if expired else "key1"
    )  # Use expired key if query parameter is present

    key_info = get_key_by_kid(kid)
    if not key_info:
        return jsonify({"error": "Key not found"}), 404

    # Create a JWT with the specified key
    expiry = datetime.utcnow() + JWT_EXPIRATION if not expired else key_info["expiry"]
    token = jwt.encode(
        {
            "sub": "test_user",
            "iss": JWT_ISSUER,
            "aud": JWT_AUDIENCE,
            "exp": expiry,
            "iat": datetime.utcnow(),
            "kid": kid,
        },
        key_info["private_key"],
        algorithm="RS256",
    )

    return jsonify({"token": token}), 200


if __name__ == "__main__":
    app.run(port=8080, debug=True)
