# Password Manager
## Overview
This Password Manager is a web application designed to securely generate passwords using, a mnemonic phrase as master key, nonces for each site/user to be able to update and change passwords still deterministically, and optional encryption/decryption of the local stored data to not having to input each time the private master key.

## Features
Getting Started
https://m.primal.net/OzRc.png

BIP39 Mnemonic Key Recovery
https://m.primal.net/OzRe.png

When Creating a password you are prompted a user and a site url and you can update the nonce for the site if you need to change the password
https://m.primal.net/OzRg.png

Optionally you can encrypt the private key and the nonces/sites data to access them faster later in the getting started screen
https://m.primal.net/OzRm.png


Here you create and back up a random seedphrase
https://m.primal.net/OzRn.png
https://m.primal.net/OzRo.png

Here you decrypt the local stored data:
https://m.primal.net/OzRp.png


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