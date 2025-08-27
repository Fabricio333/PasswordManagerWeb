import hashlib
from pathlib import Path

WORDLIST_PATH = Path(__file__).resolve().parents[1] / "static" / "bip39_wordlist.txt"
with open(WORDLIST_PATH, "r", encoding="utf-8") as f:
    WORD_LIST = {w.strip() for w in f if w.strip()}

def verify_seed_phrase(seed_phrase: str) -> bool:
    words = [w.strip() for w in seed_phrase.split()]
    if len(words) not in {12, 15, 18, 21, 24}:
        return False
    return all(word in WORD_LIST for word in words)

def derive_npub_from_nsec(nsec_hex: str) -> str:
    return hashlib.sha256(nsec_hex.encode()).hexdigest()

def derive_keys(seed_phrase: str) -> dict:
    private_key = hashlib.sha256(seed_phrase.encode()).hexdigest()
    nsec = hashlib.sha256(private_key.encode()).hexdigest()
    npub = derive_npub_from_nsec(nsec)
    return {"private_key": private_key, "nsec": nsec, "npub": npub}
