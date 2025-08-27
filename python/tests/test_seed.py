from password_manager.seed import verify_seed_phrase, derive_keys, derive_private_key
from password_manager.password import generate_password

VALID_PHRASE = (
    "abandon ability able about above absent absorb abstract absurd abuse access accident"
)
INVALID_PHRASE = (
    "abandon ability able about above absent absorb abstract xyz abuse access accident"
)


def test_verify_seed_phrase_valid():
    assert verify_seed_phrase(VALID_PHRASE)


def test_verify_seed_phrase_invalid():
    assert not verify_seed_phrase(INVALID_PHRASE)


def test_seed_to_password_matches_web():
    seed = (
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    )
    keys = derive_keys(seed)
    assert keys["private_key"] == derive_private_key(seed) == "3"
    pwd = generate_password(keys["private_key"], "user", "example.com", 1)
    assert pwd == "PASS92d74fdf59747e9a249+"
