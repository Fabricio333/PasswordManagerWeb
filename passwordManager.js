var password = document.getElementById('password')
var site = document.getElementById('site')
var entropyInput = document.getElementById('entropyInput')
var nonce = document.getElementById('nonce')
var lastResult, countResults = 0;
var entropyManualInput = document.getElementById('entropyManualInput')
var html5QrcodeScanner = new Html5QrcodeScanner(
    "qr-reader", { fps: 10, qrbox: 250 });

function onScanSuccess(decodedText, decodedResult) {
    // if (decodedText !== lastResult) {}
        ++countResults;
        lastResult = decodedText; // interesante esto del last result para mejorar la funcionalidad al repetir
        // Handle on success condition with the decoded message.
        console.log(`Scan result ${decodedText}`, decodedResult);
        // Display the result in the results container and scan result output
        // resultContainer.innerText = `Scan result ${decodedText}`;
        entropyInput.value = DecimalStringToHex(decodedText);
        document.getElementById('entropyManualInput').value = indicesToWords(decodedText)
        // QR Code Input Not Verifying the mnemonic

}

function manualEntropyInput(){
    const seedPhrase = entropyManualInput.value
        verifyBip39SeedPhrase(seedPhrase, words).then(isValid => {
        console.log(isValid);
        if(isValid){
            entropyInput.value = DecimalStringToHex(wordsToIndices(entropyManualInput.value));
        }
        else{
            alert('The Seed Phrase is Not Valid');
            throw new Error(`Checksum not valid`);
        }
    });
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

function showPassword() {
    // Load the nonces dictionary from local storage
    let nonces = loadDictionary('nonces');
    console.log('1')
    // Check if the site input is empty
    if (!site.value) {
        password.value = 'The site input is empty';
        console.log('entramo aca')
        console.log('2')
        return;
    }
    // Check if the entropy input is empty
    if (!entropyInput.value) {
        console.log('3')
        password.value = 'The entropy input is empty';
        return;
    }
    // Initialize or load the nonce for the site
    if (!nonces[site.value]) {
        nonces[site.value] = 0;
        console.log('4')
        console.log(`Initialized nonce for site: ${site.value} el nonce es: ${nonces[site.value]}`);
        saveDictionary('nonces', nonces);
    } else {
        console.log(`Loaded nonce for site: ${site.value} = ${nonces[site.value]}`);
    }

    nonce.value = nonces[site.value];

    // Generate password
    const concatenado = entropyInput.value + '@' + site.value + "/" + nonce.value ;
    console.log(concatenado);
    hashString(concatenado).then(resultado => {
        const entropiaContraseña = resultado.substring(0, 8);
        password.value = 'PASS' + entropiaContraseña + '249+';
    }).catch(error => {
        console.error('Error hashing the string:', error);
        password.value = 'Error generating password';
    });
}

function newPassword(){
    const nonces = loadDictionary('nonces')
    console.log('a ver si se estan cargando los nonces aca',nonces)
    // Check if there is a nonce already
    if(nonces[site.value] != null){
        let integerValue = +nonces[site.value]
        nonces[site.value] = integerValue + 1
        saveDictionary('nonces',nonces)
        showPassword()
    }
    else{
        console.log("there is no nonce for that website, first password shown")
        showPassword()
    }
}

function copyPasswordToClipboard(where) {
    var outputText = document.getElementById('password');
    if (!outputText.value) {
        alert("Password cannot be empty!");
        return false;
    }
    navigator.clipboard.writeText(outputText.textContent).then(
        function() {
        alert('Password copied to clipboard!');
    },
        function() {
        alert('Failed to copy text.');
    });
}

// Function to load the dictionary from local storage
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

// Function to save the dictionary to local storage
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
}

function pushNoncesToCloud(){
    // Encrypt nonces file to cloud
}
function pullNoncesFromCloud(){
    // Decrypt nonces file to cloud

}

function main(){
    html5QrcodeScanner.render(onScanSuccess);
}

main()
