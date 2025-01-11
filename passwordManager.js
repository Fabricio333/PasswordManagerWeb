var passwordField = document.getElementById('password')
var siteField = document.getElementById('site')
var nonceField = document.getElementById('nonce')
var mnemonicField = document.getElementById('mnemonicField')
var userOrMailField = document.getElementById('userOrMail')
var privateKeyField = document.getElementById('privateKey')
var settingsField = document.getElementById('settings')

function setMnemonic(mnemonic) {
    document.getElementById("mnemonicField").value = mnemonic
}

var html5QrcodeScanner = new Html5QrcodeScanner(
    "qr-reader", { fps: 10, qrbox: 250 });
function onScanSuccess(decodedText, decodedResult) {
        lastResult = decodedText; // interesante esto del last result para mejorar la funcionalidad al repetir
        // Handle on success condition with the decoded message.
        console.log(`Scan result ${decodedText}`, decodedResult);
        // Display the result in the results container and scan result output
        // resultContainer.innerText = `Scan result ${decodedText}`;
        entropyInput.value = DecimalStringToHex(decodedText);
        setMnemonic(indicesToWords(decodedText))
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
    let nonces = loadDictionary('nonces');

    // Check if the site input is empty
    if (!siteField.value) {
        alert('The site input is empty');
        return;
    }
    if (!mnemonicField.value) {
        alert('The mnemonic input is empty');
        return;
    }

    try {
        const isValid = await verifyBip39SeedPhrase(mnemonicField.value, words);
        if (isValid) {
            privateKeyField.value = DecimalStringToHex(wordsToIndices(mnemonicField.value));
        } else {
            alert('The Seed Phrase is not valid');
            throw new Error('Checksum not valid');
        }
    } catch (error) {
        console.error('An error occurred:', error);
    }

    // Initialize or load the nonce for the site
    if (!nonces[site.value]) {
        nonces[site.value] = 0;
        console.log(`Initialized nonce for site: ${site.value} el nonce es: ${nonces[site.value]}`);
        saveDictionary('nonces', nonces);
    } else {
        console.log(`Loaded nonce for site: ${site.value} = ${nonces[site.value]}`);
    }

    nonceField.value = nonces[site.value];

    const concatenado = privateKeyField.value + "/" + userOrMailField.value + "/" + siteField.value + "/" + nonce.value ;

    console.log(concatenado)
    hashString(concatenado).then(resultado => {
        const entropiaContraseña = resultado.substring(0, 16);
        password.value = 'PASS' + entropiaContraseña + '249+';
    }).catch(error => {
        console.error('Error hashing the string:', error);
        password.value = 'Error generating password';
    });
}

function newPassword(){
    const nonces = loadDictionary('nonces')
    // Check if there is a nonce already
    if(nonces[siteField.value] != null){
        let integerValue = +nonces[siteField.value]
        nonces[siteField.value] = integerValue + 1
        saveDictionary('nonces',nonces)
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
    navigator.clipboard.writeText(outputText.textContent).then(
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

function resetNonces(){
    deleteLocalStorageVariable("nonces")
    alert("Nonces Reseted Succesfully")
}

function resetSettings(){
    deleteLocalStorageVariable("settings")
    alert("Settings Reseted Succesfully")
}

function pushNoncesToCloud(){
    // Encrypt nonces file to cloud
}

function pullNoncesFromCloud(){
    // Decrypt nonces file to cloud

}

function exportSettings() {
    var nonces = loadDictionary('nonces')
    console.log(nonces)
    var settings = JSON.stringify(nonces, null, 4)
    if (Object.keys(nonces).length > 0) {
        document.getElementById('settings').value = settings
        copyElementToClipboard('settings')
    } else {
        document.getElementById('settings').value = ""
    }
}

function importSettings(){
    var settings = document.getElementById('settings')
    saveDictionary('nonces',settings)
    alert("Local Stored Settings Imported")
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
        return;
    })();
    // Example usage generateValidMnemonic().then(mnemonic => console.log("Generated Mnemonic:", mnemonic)).catch(console.error);

}

// Check inputs with common sites list
function checkSiteInput(){}

function checkEmailInput(){}

function main(){
    html5QrcodeScanner.render(onScanSuccess);
}


main()

