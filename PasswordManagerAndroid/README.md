# SecurePass Android

This folder contains the Android version of the deterministic password manager.
SecurePass derives site passwords from a BIP39 seed phrase and stores the
private key and nonce data in `EncryptedSharedPreferences` protected by
biometrics or your device credentials.

The interface is built with Jetpack Compose and prompts for fingerprint or PIN
before allowing access. Users can enter or generate a seed phrase and then
produce passwords in the same deterministic way as the web project.
