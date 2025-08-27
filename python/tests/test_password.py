from password_manager.password import generate_password
import hashlib

def test_generate_password():
    pwd = generate_password("priv", "user", "site", 1)
    combo = "priv/user/site/1"
    digest = hashlib.sha256(combo.encode()).hexdigest()[:16]
    expected = f"PASS{digest}249+"
    assert pwd == expected
