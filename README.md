# Password Manager v2: A Secure and Deterministic Approach

## Table of Contents
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
- [Using It Offline & On Mobile Devices](#using-it-offline--on-mobile-devices)
  - [Offline Usage](#offline-usage)
  - [Mobile Access](#mobile-access)
- [Potential Risks & Considerations](#potential-risks--considerations)
- [Final Thoughts](#final-thoughts)
- [Source Code](#source-code)

## **Introduction**

In today's digital world, managing passwords securely is crucial. Many password managers store your passwords online, posing potential security risks. However, this open-source Password Manager offers a unique approach: it deterministically generates different passwords for different sites and users, ensuring security without storing any passwords online. This means you can use it entirely offline and even on mobile devices without an internet connection.

---

## **Why Use This Password Manager?**

- **No Central Storage:** No passwords are stored on any server, reducing the risk of data breaches.
- **Deterministic Password Generation:** Each password is generated based on user input, meaning you get consistent passwords for the same credentials.
- **Offline Usage:** Works completely without an internet connection.
- **BIP39 Backup & Recovery:** Backing up the master key with a set of words, like on Bitcoin, ensures you never lose access to your credentials.
- **Nonce System for Changes:** Allows password updates while maintaining security and determinism on passwords creation.
- **Encryption for Local Storage:** Optionally encrypts locallly the nonces state and the private key, for convenience.

---

## **Getting Started**

### **Access the Web Version**  
Open the Password Manager here: [Password Manager Web](https://fabricio333.github.io/PasswordManagerWeb/).
   
![Getting Started](https://m.primal.net/OzRc.png)
   
### **Set Up Your Mnemonic Key**
The manager uses a BIP39 mnemonic key for secure backup and recovery. When you first start, you will need to generate and back up a seed phrase that acts as your master key.

![BIP39 Key Recovery](https://m.primal.net/OzRe.png)

### **How the Mnemonic Becomes the Private Key**
1. The seed phrase is validated by the `verifyBip39SeedPhrase` function to ensure
   all words exist in the BIP39 list and the checksum matches.
2. `wordsToIndices` converts each word to its index in the list, pads it to four
   digits, and concatenates the results into one long decimal string.
3. `decimalStringToHex` interprets that decimal string as a single big integer
   and converts it to hexadecimal form.

The resulting hex string is your private key, which is used when generating
passwords. Re-running these functions with your mnemonic will always recreate the
same key.

### **Generate a Password**
- Enter your **Username** or **Email**.
- Enter the **Website URL**.
- Let the **Nonce** on 0 if is the first password for that credentials, and modify it if you need other password.
- Press the **Show Password** button to generate the password for that credentials.
 
![Password Creation](https://m.primal.net/OzRg.png)

### **How Passwords Are Created**
Passwords are deterministically derived from four inputs:

1. **Private Key** generated from your BIP39 seed phrase.
2. Your **Username or Email**.
3. The **Website URL**.
4. A numeric **Nonce** used when you need a different password for the same site.

These values are joined with slashes and hashed using `SHA-256`. The first 16
hex characters of the hash are wrapped with `PASS` and `249+`:

```
PASS + SHA256(privateKey + '/' + username + '/' + site + '/' + nonce).substring(0,16) + '249+'
```

Using the same inputs always recreates the same password. Increase the nonce to
obtain a new password without changing your master key.
   
### **Encrypt Local Data (Optional)**  
You can choose to encrypt and save locally the private key and the nonces/sites data to speed up future access.
   
![Encryption Option](https://m.primal.net/OzRm.png)
   
### **Backup Your Seed Phrase**  
Write down and securely store your seed phrase for account recovery.
   
![Backup Seed Phrase](https://m.primal.net/OzRn.png)  

![Confirm Seed Phrase](https://m.primal.net/OzRo.png)
   
### **Decrypt Stored Data**  
If you encrypted your data, you can decrypt it to retrieve your information.
   
![Decrypt Data](https://m.primal.net/OzRp.png)

---

## **Using It Offline & On Mobile Devices**

### **Offline Usage**
This password manager does not require an internet connection. You can save the web page for offline use simply by clicking on save here on desktop, or run it locally by downloading the source code from the GitHub repository and executing it directly from the phone files manager.

---

## **Potential Risks & Considerations**

While this method is highly secure, users should keep these factors in mind:

- **Mnemonic Key Security:** Losing your seed phrase means you lose access to your passwords, create redundant back ups of the keys.
- **Local Storage Encryption:** If you encrypt your local data, ensure you remember your decryption password.
- **No Recovery Without Backup:** Unlike cloud-based password managers, if you lose your mnemonic key and haven’t backed it up, you cannot recover your credentials.
- **Phishing Risks:** Since passwords are generated deterministically, always verify you’re entering the correct site URL to avoid phishing attacks.
- **Other Users of the Same PC:** Other users could brute force the encrypted back up, make sure you use it in trusted devices and in the case of losing one device make sure you change all the passwords with a new master keys.
- **Browsers Vulnerabilities:** Being browsers the most critical part of devices the risk of a vulnerability, trojan attack, etc exists.
---

## **Final Thoughts**

This password manager provides a secure, offline, and deterministic approach to managing credentials. By utilizing BIP39 for backup and recovery and eliminating central storage, it ensures maximum security while maintaining user control. Whether you're looking for a simple and secure way to manage passwords or a fully offline solution, this tool is an excellent choice.

Try it out today: [Password Manager Web](https://fabricio333.github.io/PasswordManagerWeb/)

## **Source Code**
Explore the full source code on GitHub: [GitHub Repository](https://github.com/fabricio333/PasswordManagerWeb)

<script src="./crypto-js.min.js"></script>

## **Tasks**
- from the private key, derivate a nostr nsec and npub that will be used to sign and broadcast events to nostr relays
- By Pressing the button the user puashes its nonces dictionary in a dictionary encrypted by the private key, then it will be signed by the same private key and broadcasted to nostr relays.
- When the user wants to restore its nostr relays nonces backup and status, the latest event broadcasted by that npub gets pulled and decrypted with the main private key
- There has to be in the ui another option to edit the nonces values and push them again to edit if wrong.