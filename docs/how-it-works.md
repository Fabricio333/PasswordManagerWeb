# How It Works

This document explains the key components behind Password Manager v2: password generation, seed phrase verification and key derivation, and Nostr backup/restore.

## Password Generation Algorithm

1. After verifying or generating your seed phrase, the app builds a **private key** from the phrase.
2. When you request a password it concatenates `privateKey / username / site / nonce`.
3. The SHA-256 hash of that string is taken and the first 16 hex characters become the password entropy.
4. The final password is `PASS` + entropy + `249+`. Changing the nonce yields a new password.

## Seed Phrase Verification and Key Derivation

1. Each word in the seed phrase is validated against the BIP39 word list.
2. The words are translated to their numeric indices and combined into a long decimal string.
3. That decimal string is converted to hexadecimal and becomes the deterministic private key.
4. The private key is hashed once more with SHA-256 to derive a Nostr secret key (`nsec`), and NostrTools computes the corresponding public key (`npub`).

## Nostr Backup and Restore Flow

### Backup

1. The app derives a Nostr key pair from your private key.
2. Your session data is serialized to JSON and encrypted with `nip04`.
3. The encrypted content is wrapped in a kind `1` event tagged `nostr-pwd-backup`.
4. The event is published to a list of relays. Success on any relay completes the backup.

### Restore

1. Using the derived Nostr public key, the app queries the relays for the latest `nostr-pwd-backup` event.
2. If an event is found, its content is decrypted with `nip04` using the same key pair.
3. The decrypted JSON is loaded back into the application, restoring your saved data.
