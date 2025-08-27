from password_manager.seed import verify_seed_phrase, derive_keys
import hashlib

VALID_PHRASE = "abandon ability able about above absent absorb abstract absurd abuse access accident"
INVALID_PHRASE = "abandon ability able about above absent absorb abstract xyz abuse access accident"

def test_verify_seed_phrase_valid():
    assert verify_seed_phrase(VALID_PHRASE)

def test_verify_seed_phrase_invalid():
    assert not verify_seed_phrase(INVALID_PHRASE)

def test_derive_keys():
    keys = derive_keys(VALID_PHRASE)
    private_key_expected = hashlib.sha256(VALID_PHRASE.encode()).hexdigest()
    nsec_expected = hashlib.sha256(private_key_expected.encode()).hexdigest()
    npub_expected = hashlib.sha256(nsec_expected.encode()).hexdigest()
    assert keys["private_key"] == private_key_expected
    assert keys["nsec"] == nsec_expected
    assert keys["npub"] == npub_expected
