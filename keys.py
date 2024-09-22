# keys.py
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta
import base64

# In-memory storage for keys
keys = {}


def generate_key_pair(kid, days_valid=30):
    """Generates a new RSA key pair and stores it with kid and expiry date."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    expiry = datetime.utcnow() + timedelta(days=days_valid)

    keys[kid] = {
        "private_key": private_key,
        "public_key": public_key,
        "expiry": expiry,
        "kid": kid,
    }


def get_active_keys():
    """Returns all non-expired keys in JWKS format."""
    active_keys = []
    for kid, key_info in keys.items():
        if key_info["expiry"] > datetime.utcnow():
            active_keys.append(
                {
                    "kid": kid,
                    "kty": "RSA",
                    "alg": "RS256",
                    "use": "sig",
                    "n": int_to_base64(key_info["public_key"].public_numbers().n),
                    "e": int_to_base64(key_info["public_key"].public_numbers().e),
                }
            )
    return active_keys


def int_to_base64(n):
    """Convert an integer to a base64-encoded string."""
    return (
        base64.urlsafe_b64encode(n.to_bytes((n.bit_length() + 7) // 8, "big"))
        .rstrip(b"=")
        .decode("utf-8")
    )


def get_key_by_kid(kid):
    """Returns the private key object for a given kid."""
    return keys.get(kid)


# Generate some initial keys for testing
generate_key_pair(kid="key1", days_valid=30)
generate_key_pair(kid="expired_key", days_valid=-1)  # Expired key for testing
