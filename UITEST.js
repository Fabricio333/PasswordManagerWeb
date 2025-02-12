var seedPhrase = document.getElementById("mnemonicPhraseField");
var privateKeyField = document.getElementById("privateKeyField");
var userOrMailField = document.getElementById("userOrMailField");
var siteField = document.getElementById("siteField");
var passwordField = document.getElementById("passwordField");
var nonceField = document.getElementById("nonceField");

// Simple screen navigation logic
function showScreen(screenId) {
    document.querySelectorAll('.screen').forEach(screen => {
        screen.classList.add('hidden');
    });
    document.getElementById(screenId).classList.remove('hidden');
}
function decimalStringToHex(DecimalString) {
    // Check if the input is a valid number
    if (!/^\d+$/.test(DecimalString)) {
        throw new Error("Input must be a valid decimal string.");
    }
    const decimalNumber = BigInt(DecimalString); // Convert string to BigInt
    const hexadecimal = decimalNumber.toString(16); // Convert to hexadecimal
    return hexadecimal;
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

async function verifySeedAndMoveNext() {
    try {
        // Await the result of the async function
        var isValid = await verifyBip39SeedPhrase(seedPhrase.value, words);
        if (isValid) {
            alert("Seed phrase is valid");
            console.log(seedPhrase.value)
            console.log(decimalStringToHex(wordsToIndices(seedPhrase.value)))
            console.log(wordsToIndices(seedPhrase.value))
            privateKeyField.value = decimalStringToHex(wordsToIndices(seedPhrase.value));
            showScreen('managementScreen'); // Move to the next screen
        } else {
            alert("Seed phrase is not valid");
        }
    } catch (error) {
        console.error("Error verifying seed phrase:", error);
        alert("An error occurred while verifying the seed phrase");
    }
}
function hash(text) {
    return CryptoJS.SHA256(text).toString();

}
async function showPassword() {
/*
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
*/

    /*
    prepare all the verification processes to ensure proper data input
    */
    const concatenado = privateKeyField.value + "/" + userOrMailField.value + "/" + siteField.value + "/" + nonceField.value ;
    console.log(concatenado)

        const entropiaContraseña = hash(concatenado).substring(0, 16);
        passwordField.value = 'PASS' + entropiaContraseña + '249+';
}