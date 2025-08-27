import hashlib

def generate_password(private, user, site, n):
    combo = f"{private}/{user}/{site}/{n}"
    digest = hashlib.sha256(combo.encode()).hexdigest()[:16]
    return f"PASS{digest}249+"


