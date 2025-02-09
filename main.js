var passwordField = document.getElementById('password')
var siteField = document.getElementById('site')
var nonceField = document.getElementById('nonce')
var mnemonicField = document.getElementById('mnemonicField')
var userOrMailField = document.getElementById('userOrMail')
var privateKeyField = document.getElementById('privateKey')
var localStoredData = {}
var html5QrcodeScanner = new Html5QrcodeScanner(
    "qr-reader", { fps: 10, qrbox: 250 });
var lastResult = ""
var localStoredStatus = ""
/*
Local Stored Data is stored encrypted with the following structure:
var localStoredData = {
    "privateKey": "asdfgqwerasdfg",
    "users": {
        "bob123": {
            "facebook.com": 0,
            "site2": 0
        },
        "bob@bob.com": {
            "google.com": 0,
            "site2": 0
        }
    }
};

With a password sensible data is encrypted like the following:

localStorage("encryptedDataStorage") = {
hash(password) : encrypted(localStoredData, password),
hash(password2) : encrypted(localStoredData2, password2)
}

Add safety measures like alerting that a password is new for that site.
Alerting that was pressed the new password for a site N=1
Adding a variable to alerting to press to times when overwriting with new data the local Stored Data, not always just when data differs from previious.
*/

function setMnemonic(mnemonic) {
    document.getElementById("mnemonicField").value = mnemonic
}


async function onScanSuccess(decodedText, decodedResult) {
    if (lastResult == decodedText){
        alert("This private key is already scanned.")
        return;
    }

        // Handle on success condition with the decoded message.
        console.log(`Scan result ${decodedText}`, decodedResult);
        // Display the result in the results container and scan result output
        // resultContainer.innerText = `Scan result ${decodedText}`;
        setMnemonic(indicesToWords(decodedText))
        alert("QR Mnemnonic Scanned Succesfully")
    try {
        const isValid = await verifyBip39SeedPhrase(mnemonicField.value, words);
        if (isValid) {
            privateKeyField.value = DecimalStringToHex(wordsToIndices(mnemonicField.value));
        } else {
            alert('The Seed Phrase is not valid');
            throw new Error('Checksum not valid');
        }
    } catch (error) {
        console.error('An error verifying seed phrase occurred:', error);
    }
}

async function hashString(stringToHash) {
    // Check if the input is empty
    if (!stringToHash) {
        console.log('The input to hash is empty');
        return '';
    }

    try {
        // Ensure the text is normalized and encoded in UTF-8
        const encoder = new TextEncoder();
        const data = encoder.encode(stringToHash.normalize('NFC')); // Normalize to NFC form

        // Generate the SHA-256 hash
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);

        // Convert the hash buffer to a hex string
        const hashedValue = Array.from(new Uint8Array(hashBuffer))
            .map(byte => byte.toString(16).padStart(2, '0'))
            .join('');

        // Return the hashed value directly
        return hashedValue

    } catch (error) {
        // Handle potential errors
        console.error('Error generating hash:', error);
        return '';
    }
}

function DecimalStringToHex(DecimalString) {
    // Check if the input is a valid number
    if (!/^\d+$/.test(DecimalString)) {
        throw new Error("Input must be a valid decimal string.");
    }

    const decimalNumber = BigInt(DecimalString); // Convert string to BigInt
    const hexadecimal = decimalNumber.toString(16); // Convert to hexadecimal
    return hexadecimal;
}

async function showPassword() {
    // Load the nonces dictionary from local storage

    if (!localStoredData["users"]) {
        localStoredData["users"] = {};
    }
    if (!localStoredData["users"][userOrMailField.value]) {
        alert("A password for a new user or email is being created.")
        localStoredData["users"][userOrMailField.value] = {};
    }
    // Check if the site input is empty
    if (!siteField.value) {
        alert('The site input is empty');
        return;
    }
    let nonces = localStoredData["users"][userOrMailField.value]



    if (!privateKeyField.value) {
        try {
            const isValid = await verifyBip39SeedPhrase(mnemonicField.value, words);
            if (isValid) {
                privateKeyField.value = DecimalStringToHex(wordsToIndices(mnemonicField.value));
            } else {
                alert('The Seed Phrase is not valid');
                throw new Error('Checksum not valid');
            }
        } catch (error) {
            console.error('An error verifying seed phrase occurred:', error);
        }
    }
    
    // Initialize or load the nonce for the site
    if (!nonces[siteField.value]) {
        alert("A password for a new site is being created.")
        localStoredData["users"][userOrMailField.value][siteField.value] = 0;
        nonces = localStoredData["users"][userOrMailField.value]
        console.log(`Initialized nonce for site: ${siteField.value} el nonce es: ${nonces[siteField.value]}`);
    } else {
        console.log(`Loaded nonce for site: ${siteField.value} = ${nonces[siteField.value]}`);
    }

    nonceField.value = localStoredData["users"][userOrMailField.value][siteField.value];
    const concatenado = privateKeyField.value + "/" + userOrMailField.value + "/" + siteField.value + "/" + nonces[siteField.value] ;
    console.log(concatenado)

    hashString(concatenado).then(resultado => {
        const entropiaContraseña = resultado.substring(0, 16);
        passwordField.value = 'PASS' + entropiaContraseña + '249+';
    }).catch(error => {
        console.error('Error hashing the string:', error);
        passwordField.value = 'Error generating password';
    });
    console.log(localStoredData)
}

function newPassword(){
    if (!localStoredData["users"]) {
        localStoredData["users"] = {};
    }
    if (!localStoredData["users"][userOrMailField.value]) {
        localStoredData["users"][userOrMailField.value] = {};
    }
    const nonces = localStoredData["users"][userOrMailField.value]

    // Check if there is a nonce already
    if(nonces[siteField.value] != null){
        let integerValue = +nonces[siteField.value]
        nonces[siteField.value] = integerValue + 1
        localStoredData["users"][userOrMailField.value] = nonces
        showPassword()
    }
    else{
        console.log("there is no previous nonce for that website")
        showPassword()
    }
}

function copyElementToClipboard(element) {
    var outputText = document.getElementById(element);
if (outputText && !outputText.value.trim()) { // Check if selected text is empty or null
        alert("Selected text is empty!");
        return false;
}
    navigator.clipboard.writeText(outputText.value).then(
        function() {
        alert('Copied Succesfully to clipboard!');
    },
        function() {
        alert('Failed to copy text.');
    });
}

function loadDictionary(key) {
    // Check if the key exists in localStorage
    const storedData = localStorage.getItem(key);
    // If data exists, parse it, otherwise return an empty object
    if (storedData) {
        return JSON.parse(storedData);
    } else {
        return {};  // Return an empty object if nothing is found
    }
}

function saveDictionary(key, dictionary) {
    // Convert the dictionary to a JSON string and save it in localStorage
    localStorage.setItem(key, JSON.stringify(dictionary));
    console.log('Dict Saved')
}

function indicesToWords(indexString) {
    const wordsArray = [];
    // Process the string in chunks of four characters
    for (let i = 0; i < indexString.length; i += 4) {
        const indexChunk = indexString.substring(i, i + 4);
        const index = parseInt(indexChunk, 10);

        if (index < 0 || index >= words.length) {
            throw new Error(`Index "${index}" is out of bounds.`);
        }

        const word = words[index];
        wordsArray.push(word);
    }
    // Join the words with a space separator
    return wordsArray.join(' ');
}

function wordsToIndices(inputWords) {
    // Ensure inputWords is a string
    if (typeof inputWords !== "string") {
        throw new TypeError("inputWords must be a string");
    }

    // Split the string into an array of words
    const wordsArray = inputWords.split(" ");

    // Map each word to its index and pad the result, then join into a single string
    return wordsArray.map(word => {
        const index = words.indexOf(word);
        if (index === -1) {
            alert(`Word "${word}" not found in the list.`);
            throw new Error(`Word "${word}" not found in the list.`);


        }
        // Convert the index to a string with leading zeros
        return index.toString().padStart(4, '0');
    }).join('');
}

async function verifyBip39SeedPhrase(seedPhrase, wordlist) {
    /**
     * Verifies a BIP-39 seed phrase.
     * @param {string} seedPhrase - The seed phrase input as a string of words.
     * @param {string[]} wordlist - The BIP-39 wordlist to validate the words.
     * @returns {Promise<boolean>} - A promise that resolves to true if the seed phrase is valid, false otherwise.
     */
    const words = seedPhrase.trim().split(/\s+/);
    const wordCount = words.length;

    // Validate word count (12, 15, 18, 21, 24 are the only valid lengths)
    if (![12, 15, 18, 21, 24].includes(wordCount)) {
        return false;
    }

    // Validate that all words exist in the wordlist
    if (!words.every(word => wordlist.includes(word))) {
        return false;
    }

    // Calculate total bits, entropy bits, and checksum bits
    const totalBits = wordCount * 11; // Each word represents 11 bits
    const checksumBits = totalBits % 32;
    const entropyBits = totalBits - checksumBits;

    // Convert words to binary representation
    const binaryString = words
        .map(word => wordlist.indexOf(word).toString(2).padStart(11, '0'))
        .join('');

    // Split binary string into entropy and checksum
    const entropy = binaryString.slice(0, entropyBits);
    const checksum = binaryString.slice(entropyBits);

    // Convert entropy binary string to a Uint8Array
    const entropyBytes = new Uint8Array(entropy.length / 8);
    for (let i = 0; i < entropy.length; i += 8) {
        entropyBytes[i / 8] = parseInt(entropy.slice(i, i + 8), 2);
    }

    // Calculate the SHA-256 hash of the entropy
    const hashBuffer = await crypto.subtle.digest('SHA-256', entropyBytes);
    const hashArray = new Uint8Array(hashBuffer);

    // Convert hash to binary string
    const hashBinary = Array.from(hashArray)
        .map(byte => byte.toString(2).padStart(8, '0'))
        .join('');

    // Compare the calculated checksum with the provided checksum
    return checksum === hashBinary.slice(0, checksumBits);
}

function deleteLocalStorageVariable(key) {
    if (localStorage.getItem(key) !== null) {
        localStorage.removeItem(key);
        console.log(`The variable '${key}' has been deleted from local storage.`);
    } else {
        console.log(`The variable '${key}' does not exist in local storage.`);
    }
}

function resetNonces(){ // modify to reset just the nonce of the current website
    deleteLocalStorageVariable("nonces")
    alert("Nonces Reseted Succesfully")
}

function deleteLocalStoredData() { //
    /*
    Deletes all the stored data for a password, try to find a way to double check that,
    also prevent to encrypt and erase with 0 data, it shouldn't happen if data was already loaded,
    sorry it can happen if there is no loaded data,
    a password is in the input and the "encrypt" button is pressed
    */

}

function generateValidMnemonic() {
    if (words.length !== 2048) {
        throw new Error("The wordlist must contain exactly 2048 words.");
    }

    // Step 1: Generate cryptographically secure random entropy
    function generateEntropy(bytes = 16) {
        if (window.crypto && window.crypto.getRandomValues) {
            const entropy = new Uint8Array(bytes);
            window.crypto.getRandomValues(entropy);
            return entropy;
        } else {
            throw new Error("Secure random generation not supported in this browser.");
        }
    }

    // Step 2: Convert entropy to binary string
    function entropyToBinary(entropy) {
        return Array.from(entropy)
            .map(byte => byte.toString(2).padStart(8, "0"))
            .join("");
    }

    // Step 3: Generate checksum (Fixed to handle async digest)
    async function generateChecksum(entropy) {
        const hashBuffer = await window.crypto.subtle.digest("SHA-256", entropy);
        const hashArray = new Uint8Array(hashBuffer);
        const hashBinary = Array.from(hashArray)
            .map(byte => byte.toString(2).padStart(8, "0"))
            .join("");
        const checksumBits = (entropy.length * 8) / 32; // Entropy length in bits / 32
        return hashBinary.substring(0, checksumBits);
    }

    // Step 4: Convert binary to mnemonic words
    function binaryToMnemonic(binary, wordlist) {
        const words = [];
        for (let i = 0; i < binary.length; i += 11) {
            const index = parseInt(binary.slice(i, i + 11), 2);
            words.push(wordlist[index]);
        }
        return words.join(" ");
    }

    // Generate the mnemonic
    return (async () => {
        const entropy = generateEntropy();
        const entropyBinary = entropyToBinary(entropy);
        const checksum = await generateChecksum(entropy); // Await the async checksum
        const mnemonicBinary = entropyBinary + checksum;
        var mnemonic = binaryToMnemonic(mnemonicBinary, words)
        setMnemonic(mnemonic)
        privateKeyField.value = DecimalStringToHex(wordsToIndices(mnemonicField.value));        return;
    })();
    // Example usage generateValidMnemonic().then(mnemonic => console.log("Generated Mnemonic:", mnemonic)).catch(console.error);

}

// Flag variable to keep track of whether settings are visible or not
let settingsVisible = false;
function toggleSettings() {
    // Get reference to #toggle-container element
    const container = document.getElementById('toggle-container');

    // If settings are currently visible, hide them; otherwise show them
    if (settingsVisible) {
        container.style.display = 'none';
    } else {
        container.style.display = 'block';
    }

    // Toggle the flag variable to remember new state
    settingsVisible = !settingsVisible;
}

let QRScannerVisible = false;
function toggleQRReader(){
    // Get reference to #toggle-container element
    const container = document.getElementById('qr-reader');

    if (!QRScannerVisible){
        container.style.display = 'block';
        html5QrcodeScanner.render(onScanSuccess);
        QRScannerVisible = !QRScannerVisible;
    }
    else{
        container.style.display = 'none';
        QRScannerVisible = !QRScannerVisible;
    }
}
// Check inputs with common sites list

function checkSiteInput(){}
// Show an alert that the site is new.
function checkEmailInput(){}
//
function pushNoncesToCloud(){
    // Encrypt nonces file to cloud
}
//
function pullNoncesFromCloud(){
    // Decrypt nonces file to cloud

}


// function to import/export settings

// Hash the password
function hashPassword(password) {
    return CryptoJS.SHA256(password).toString();

}

function hashInput(input){
    return CryptoJS.SHA256(input).toString();
}
function loadEncryptedData() {
    const passwordInput = document.getElementById('encryptionPassword');
    const password = passwordInput.value.trim();
    if (!password || !passwordInput) {
        alert('No password to load encrypted data, no local storage will be used.');
        return {};
    }

    try {
        const key = hashPassword(password); // Use the hashed password to retrieve the encrypted data
        const storedData = loadDictionary("encryptedDataStorage") || {}; // Load the dictionary

        if (!storedData || typeof storedData !== 'object') {
            alert('No stored data found or invalid data format.');
            return;
        }

        const encryptedData = storedData[key]; // Retrieve the encrypted data using the hashed key
        if (!encryptedData) {
            alert('No data found for the provided password.');
            return;
        }

        console.log('Encrypted data:', encryptedData);

        // Decrypt the data using the raw password
        const decryptedBytes = CryptoJS.AES.decrypt(encryptedData, password);
        const decryptedData = decryptedBytes.toString(CryptoJS.enc.Utf8);

        if (!decryptedData) {
            throw new Error('Failed to decrypt data. Possibly malformed UTF-8.');
        }

        console.log('Decrypted data:', decryptedData);
        localStoredData = JSON.parse(decryptedData)
        if(!localStoredData["privateKey"]){
            alert("There is no private key in the decrypted storage.")
            return;
        }
        privateKeyField.value = localStoredData["privateKey"]
        /*mnemonicField.value = HexToMnemonic()
        */
        localStoredStatus = "loaded"
        alert('Data loaded successfully.');
        return localStoredData; // Parse the JSON string back into an object
    } catch (error) {
        console.error('Error during decryption or parsing:', error.message);
        alert('Failed to decrypt. Invalid password or corrupted data.');
    }
}

function saveEncryptedData() {
    const password = document.getElementById('encryptionPassword').value;
    if (!password) {
        alert('Please enter a password.');
        return;
    }

    if (Object.keys(localStoredData).length === 0) {
        alert('There is no data to save.');
        return;
    }
    if(localStoredStatus === "loaded"){
        alert("Overwriting encrypted storage, press again to confirm.")
        localStoredStatus = "confirmingDeletion"
        return;
    }
    if(localStoredStatus === "confirmingDeletion"){
        localStoredStatus = ""
        return;
    }
    localStoredData["privateKey"] = privateKeyField.value

    const key = hashPassword(password); // Use the hashed password as the dictionary key
    const encrypted = CryptoJS.AES.encrypt(JSON.stringify(localStoredData), password).toString(); // Encrypt with the raw password

    // Load existing dictionary from localStorage
    const existingData = loadDictionary("encryptedDataStorage") || {};
    existingData[key] = encrypted; // Save the encrypted data using the hashed password as the key
    saveDictionary("encryptedDataStorage", existingData); // Save back to localStorage
    console.log('Data saved with hashed key:', key);
    console.log('Data:', existingData[key]);
    alert("Data encrypted succesfully")
}


function deleteEncryptedData(){
    localStorage.setItem("encryptedDataStorage", JSON.stringify({}));
    console.log("Encrypted Storage Deleted Succesfully")
}

const passwordInput = document.getElementById("encryptionPassword");
const togglePassword = document.getElementById("togglePassword");

togglePassword.addEventListener("click", function () {
    // Toggle password visibility
    const type =
        passwordInput.getAttribute("type") === "password" ? "text" : "password";
    passwordInput.setAttribute("type", type);

    // Change the icon (optional)
    this.textContent = type === "password" ? "👁️" : "🙈";
});

// Missing HEX to Bip39 Mnemonic