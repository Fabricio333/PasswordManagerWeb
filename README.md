# Password Manager
## Overview
This Password Manager is a web application designed to securely generate passwords using, a mnemonic phrase as master key, nonces for each site/user to be able to update and change passwords still deterministically, and optional encryption/decryption of the local stored data to not having to input each time the private master key.

## Features
Mnemonic Phrase Generation and Validation: Generate and validate BIP-39 mnemonic phrases to ensure secure password derivation.
QR Code Scanning: Use the QR code scanner to input entropy for password generation.
Secure Password Generation: Generate strong, site-specific passwords using a combination of mnemonic phrases, user credentials, and site information.
Nonce Management: Automatically manage nonces for each site to ensure unique password generation.
Local Storage: Save nonces and settings locally for persistence across sessions.
Clipboard Copying: Easily copy generated passwords and settings to the clipboard for quick access.
Settings Export/Import: Export and import settings to backup or restore your configuration.
Reset Functions: Reset nonces and settings to start fresh if needed.
How to Use
Setup:
Ensure your browser supports the necessary cryptographic APIs.
Open the application in a web browser.
Generating a Mnemonic:
Use the "Generate Mnemonic" feature to create a new BIP-39 seed phrase.
Validate the mnemonic using the provided wordlist.
QR Code Scanning:
Use the QR code scanner to input entropy for your password generation.
Password Generation:
Enter the site name, user credentials, and mnemonic phrase.
Click "Show Password" to generate a password for the specified site.
Use "New Password" to increment the nonce and generate a new password.
Managing Nonces:
Nonces are automatically managed and stored in local storage.
Use "Reset Nonces" to clear all stored nonces.
Settings Management:
Export settings to backup your configuration.
Import settings to restore from a backup.
Copying to Clipboard:
Use the "Copy" feature to copy passwords and settings to the clipboard.
Completed Tasks
Implemented mnemonic phrase generation and validation.
Integrated QR code scanning for entropy input.
Developed secure password generation logic.
Implemented nonce management and local storage functionality.
Added settings export and import features.
Created clipboard copying functionality.
Developed user interface for all core features.
Pending Tasks
Implement cloud synchronization for nonces and settings.
Enhance user interface for better usability and aesthetics.
Add support for additional languages in the wordlist.
Improve error handling and user feedback for edge cases.
Conduct thorough testing for edge cases and security vulnerabilities.
Contributing
Contributions are welcome! Please feel free to submit a pull request or open an issue for any bugs or feature requests.
License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
Contact
For questions or support, please contact [Your Name] at [Your Email].

## Tasks 
- [x] Alerting when a new website is detected when creating a password, avoiding typos. (just useful if there was previousStoredData)
- [x] Alerting in the same way when a new user/email is detected
- [ ] Export/ Import of localStorage
- [ ] Converting hex private key to words again if needed (button)
- [ ] Is there any way to set temporal duration to the localStorage data? (Check example script)
- [ ] Pressing two times to overwrite encrypted data (alert first)
- [ ] If different passwords are input everything will fail, alerts will fail, the page needs to be refreshed for that.
- [ ] Check for empty spaces on inputs and don't allow them
- [ ] "Enter Pressed on Confirm Screen on management saving encrypted data screen"