# Password Manager Android

This folder contains a minimal Android implementation of the deterministic password manager. The app uses the same BIP39 based algorithm as the web version but stores the private key and nonce data in `EncryptedSharedPreferences`. Biometric authentication can be configured by the OS when unlocking the encrypted preferences.

The interface is built with Jetpack Compose and allows users to enter or generate a seed phrase, then produce passwords for a given username, site and nonce. Generated passwords follow the same deterministic scheme as the original project.
