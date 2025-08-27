import hashlib

def generate_password(private_key: str, username: str, site: str, nonce: int) -> str:
    combo = f"{private_key}/{username}/{site}/{nonce}"
    digest = hashlib.sha256(combo.encode()).hexdigest()[:16]
    return f"PASS{digest}249+"
