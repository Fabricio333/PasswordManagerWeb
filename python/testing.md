# Testing Guidelines

This document outlines suggested strategies for exercising the Python password
manager implementation.  Automated tests live in `tests/`, but the following
notes describe additional manual checks and rationale for each module.

## Verify Password Derivation Against the Web Version

1. Launch `index.html` from the project root in a browser.
2. Enter a master password, username, site name, and counter; record the
   generated password.
3. From the same values run the Python generator:
   ```bash
   python - <<'PY'
   from password_manager.password import generate_password
   print(generate_password("master", "user", "example.com", 1))
   PY
   ```
4. Confirm that the value matches the one produced by the web interface.
5. Repeat with different inputs to ensure the prefix `PASS`, SHA‑256 digest
   truncation, and `249+` suffix rules are consistent.

## Seed Phrase Utilities

- **`verify_seed_phrase`** – Provide known valid and invalid BIP‑39 phrases to
  check wordlist membership and word count boundaries.
- **`derive_private_key` & `derive_keys`** – Use fixed phrases to ensure the
  derived private key, `nsec`, and `npub` match expected vectors.  Compare
  outputs with the web version when available.
- **`generate_seed_phrase`** – Call with default and alternate strengths
  (128–256 bits) and verify word count and that `verify_seed_phrase` accepts the
  result.

## Nostr Backup and Restore

- **`backup_to_nostr`** – Ensure the function writes an encrypted event to the
  local backup file and returns an event id.  When relay URLs are supplied,
  verify WebSocket logging and successful publication.
- **`restore_from_nostr`** – With the backup file present, confirm data is
  decrypted correctly.  Delete the local file to force fetching from a relay and
  assert the round‑tripped payload matches the original.
- **`restore_history_from_nostr`** – Create multiple backups and verify that the
  returned list reflects chronological ordering and complete history.
- When the optional `python-nostr` library is installed, repeat the above to
  ensure event creation and NIP‑04 encryption behave identically.

## Application Interfaces

- **`app.py` (CLI)** – Run the program with sample arguments and ensure it
  prints deterministic passwords and handles missing options gracefully.
- **`gui.py`** – Manual testing: start the Tkinter interface, generate passwords
  and seeds, and confirm clipboard or display behaviour.

## Running the Test Suite

Execute all automated tests with:

```bash
pytest -q
```

Consider extending coverage with edge cases such as empty inputs, network
failures, and missing optional dependencies.
