# Password Manager v2: A Secure and Deterministic Approach

## Table of Contents
- [Why Use This Password Manager?](#why-use-this-password-manager)
- [Getting Started](#getting-started)
  - [Access the Web Version](#access-the-web-version)
  - [Set Up Your Mnemonic Key](#set-up-your-mnemonic-key)
  - [Generate a Password](#generate-a-password)
  - [Backup Your Seed Phrase](#backup-your-seed-phrase)
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
- **Secure Local Storage:** On Android, data is protected by the device's encryption.

---

## **Getting Started**

### **Access the Web Version**  
Open the Password Manager here: [Password Manager Web](https://fabricio333.github.io/PasswordManagerWeb/).
   
![Getting Started](https://m.primal.net/OzRc.png)
   
### **Set Up Your Mnemonic Key**  
The manager uses a BIP39 mnemonic key for secure backup and recovery. When you first start, you will need to generate and back up a seed phrase that acts as your master key.
   
![BIP39 Key Recovery](https://m.primal.net/OzRe.png)
   
### **Generate a Password**  
- Enter your **Username** or **Email**.
- Enter the **Website URL**.
- Let the **Nonce** on 0 if is the first password for that credentials, and modify it if you need other password.
- Press the **Show Password** button to generate the password for that credentials.
 
![Password Creation](https://m.primal.net/OzRg.png)

### **Backup Your Seed Phrase**
Write down and securely store your seed phrase for account recovery.
   
![Backup Seed Phrase](https://m.primal.net/OzRn.png)  

![Confirm Seed Phrase](https://m.primal.net/OzRo.png)
   

## **Using It Offline & On Mobile Devices**

### **Offline Usage**
This password manager does not require an internet connection. You can save the web page for offline use simply by clicking on save here on desktop, or run it locally by downloading the source code from the GitHub repository and executing it directly from the phone files manager.

### **Mobile Access**

An Android wrapper is provided in the `android` folder. If you tag your commit
with `v*` or run the GitHub Actions workflow manually, the APK will be built and
attached to the release automatically.  To build it yourself:

1. Install Android Studio and open the `android` directory as a project.
2. Wait for Gradle to sync and download dependencies.
3. From the menu choose **Build → Build APK(s)**.
4. The generated file will appear under `app/build/outputs/apk/release`.
=======
An Android wrapper is provided in the `android` folder. Tag your commit with `v*`
or run the GitHub Actions workflow manually to build the APK automatically. The
generated file is attached to the release so you can install it on your device
without setting up Android Studio.

### **Improved Android Experience**
The Android app now includes a native bottom navigation bar and Material styling for better responsiveness. Stored data can be unlocked using either fingerprint or your device PIN thanks to `BiometricPrompt` with device credential fallback.

---

## **Potential Risks & Considerations**

While this method is highly secure, users should keep these factors in mind:

- **Mnemonic Key Security:** Losing your seed phrase means you lose access to your passwords, create redundant back ups of the keys.
- **Local Data Security:** Local data is stored using your device's encryption. Avoid using untrusted browsers.
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



## Tasks 
- [x] Alerting when a new website is detected when creating a password, avoiding typos. (just useful if there was previousStoredData)
- [x] Alerting in the same way when a new user/email is detected
- [ ] Export/ Import of localStorage
- [ ] Converting hex private key to words again if needed (button)
- [ ] Is there any way to set temporal duration to the localStorage data? (Check example script)
- [ ] If different passwords are input everything will fail, alerts will fail, the page needs to be refreshed for that.
- [ ] Check for empty spaces on inputs and don't allow them
