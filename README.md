# Password Manager v2
A deterministic password vault with optional Nostr cloud backups.

For a deeper technical overview, see [How It Works](docs/how-it-works.md).

## Table of Contents
- [How It Works](docs/how-it-works.md)
- [Introduction](#introduction)
- [Why Use This Password Manager?](#why-use-this-password-manager)
- [Getting Started](#getting-started)
  - [Access the Web Version](#access-the-web-version)
  - [Set Up Your Mnemonic Key](#set-up-your-mnemonic-key)
  - [How the Mnemonic Becomes the Private Key](#how-the-mnemonic-becomes-the-private-key)
  - [Generate a Password](#generate-a-password)
  - [How Passwords Are Created](#how-passwords-are-created)
  - [Encrypt Local Data (Optional)](#encrypt-local-data-optional)
  - [Backup Your Seed Phrase](#backup-your-seed-phrase)
  - [Decrypt Stored Data](#decrypt-stored-data)
- [Nostr Integration](#nostr-integration)
  - [Key Derivation](#key-derivation)
  - [Backing Up to Nostr](#backing-up-to-nostr)
  - [Restoring from Nostr](#restoring-from-nostr)
  - [Backup History](#backup-history)
- [Using It Offline & On Mobile Devices](#using-it-offline--on-mobile-devices)
- [Potential Risks & Considerations](#potential-risks--considerations)
- [Final Thoughts](#final-thoughts)
- [Source Code](#source-code)

## Introduction
This project is a single-page password manager that never stores your passwords. Instead, it deterministically derives them from a BIP39 seed phrase combined with your username, the site domain and a nonce. It can run entirely offline and even works from a mobile browser.

---

## Why Use This Password Manager?
- **No Central Storage** – passwords are never uploaded anywhere.
- **Deterministic Generation** – get the same password every time for the same inputs.
- **Offline Ready** – the app works without an internet connection.
- **BIP39 Backup** – your master key can be written down as a standard seed phrase.
- **Nonce System** – change a password by increasing the nonce value.
- **Optional Local Encryption** – save encrypted session data in the browser for convenience.

---

## Getting Started
### Access the Web Version
Open [Password Manager Web](https://fabricio333.github.io/PasswordManagerWeb/) in your browser. You can also download the repo and open `index.html` directly for offline use.

### Set Up Your Mnemonic Key
Generate or restore a BIP39 seed phrase. This phrase is your master key – keep it safe.

### How the Mnemonic Becomes the Private Key
1. Each word is validated against the BIP39 list and turned into its numeric index.
2. The indices form a long decimal string that is converted to hexadecimal.
3. This hex string is your raw private key used for password generation.

### Generate a Password
1. Enter your username or email.
2. Enter the website URL.
3. Adjust the nonce if you need multiple passwords for the same site.
4. Click **Show Password**.

### How Passwords Are Created
The password is:
```text
PASS + SHA256(privateKey + '/' + username + '/' + site + '/' + nonce).substring(0,16) + '249+'
```
Increment the nonce to produce a new password while keeping the same seed phrase.

### Encrypt Local Data (Optional)
You can encrypt your session data (private key and nonce dictionary) with a password so it is stored securely in localStorage.

### Backup Your Seed Phrase
Always write down your seed phrase so you can recover your vault.

### Decrypt Stored Data
Use the same encryption password to load previously stored session data.

---

## Nostr Integration
The application can optionally back up your encrypted state using the [Nostr](https://nostr.com/) protocol.

### Key Derivation
When you verify your seed phrase, it is hashed once with SHA‑256. The result becomes the Nostr secret key (`nsec`). The corresponding public key (`npub`) is derived with `NostrTools`. This happens in `verifySeedAndMoveNext`.

### Backing Up to Nostr
The function `backupToNostr` encrypts your session data using `nip04` with your own key pair and publishes it as a kind `1` event tagged `nostr-pwd-backup` to multiple relays:
```javascript
const event = {
    kind: 1,
    pubkey: pk,
    created_at: Math.floor(Date.now() / 1000),
    tags: [["t", "nostr-pwd-backup"]],
    content: encrypted,
};
```
Each relay is contacted and the event is signed with your `nsec` before being sent.

### Restoring from Nostr
`restoreFromNostr` downloads the latest backup event from the relays using your `npub`, decrypts it with `nip04` and loads the data back into the app.

### Backup History
`openNostrHistory` lists all past backup events found across relays. Tapping one uses `restoreFromNostrId` to load that specific event. You can also manually paste an event ID from the **Restore Using Event ID** screen.

---

## Using It Offline & On Mobile Devices
Simply save the web page or open it directly from the repository on your device. All features, including password generation, work without a network connection. Nostr backups obviously require connectivity.

---

## Potential Risks & Considerations
- **Seed Phrase Security** – losing it means losing your vault.
- **Local Storage Encryption** – forget the password and the data is unreadable.
- **Phishing** – double‑check site URLs when generating passwords.
- **Browser Security** – a compromised browser could leak your seed phrase.

---

## Final Thoughts
This project offers a lightweight password solution with an optional decentralised backup powered by Nostr. Because everything is deterministic, you remain in control of your credentials at all times.

Try it out: [Password Manager Web](https://fabricio333.github.io/PasswordManagerWeb/)

## Source Code
View the full code on [GitHub](https://github.com/fabricio333/PasswordManagerWeb).
