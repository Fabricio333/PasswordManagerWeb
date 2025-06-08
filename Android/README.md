# Android Password Manager

This directory contains a minimal Android application that mirrors the functionality of the web version of the password manager.

The project uses **Kotlin** and **Jetpack Compose**. Due to the minimal setup, you may need to open the `Android` folder in Android Studio to build and run the app.

## Features
- Import or generate a BIP39 mnemonic on first launch
- Protect the mnemonic using the device's biometric or PIN
- Derive passwords deterministically using the site, user and nonce
- Delete locally stored data from the management panel

## Building
Open the `Android` folder with Android Studio (Arctic Fox or newer) and let Gradle sync. The project targets SDK 34.

