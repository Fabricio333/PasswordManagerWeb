var seedPhraseField = document.getElementById("seedPhraseField");
var privateKeyField = document.getElementById("privateKeyField");
var userOrMailField = document.getElementById("userOrMailField");
var siteField = document.getElementById("siteField");
var passwordField = document.getElementById("passwordField");
var nonceField = document.getElementById("nonceField");
var seedPhraseField = document.getElementById("seedPhraseField");
var newSeedPhraseField = document.getElementById("newSeedPhraseField");
var localStoredData = {}
var localStoredStatus = ""
// Navigation history stack
const navigationHistory = ["welcomeScreen"];
let currentScreenId = "welcomeScreen";

// Fixed showScreen function to track navigation history correctly
function showScreen(screenId, isBackNavigation = false) {
    // Hide all screens
    document.querySelectorAll('.screen').forEach(screen => {
        screen.classList.add('hidden');
    });

    // Show the target screen
    const targetScreen = document.getElementById(screenId);
    if (targetScreen) {
        targetScreen.classList.remove("hidden");

        // Only update history if this is not a back navigation
        if (!isBackNavigation && currentScreenId !== screenId) {
            navigationHistory.push(currentScreenId);
            currentScreenId = screenId;
        } else if (isBackNavigation) {
            // Just update current screen ID without modifying history
            currentScreenId = screenId;
        }
    } else {
        alert("Screen Change Failed");
    }

    // Initialize verification screen if needed
    if (screenId === "verifySeedBackUpScreen") {
        setupVerificationScreen();
        // Clear any previous verification message
        document.getElementById("verificationResult").textContent = "";
    }

    console.log("Navigation History:", navigationHistory);
}

// Improved function to navigate back
function navigateBack(currentScreen) {
    // Don't proceed if we're already at the welcome screen or history is empty
    if (navigationHistory.length <= 1) {
        showScreen("welcomeScreen", true);
        navigationHistory.length = 0;
        navigationHistory.push("welcomeScreen");
        return;
    }

    // Get the previous screen
    const previousScreen = navigationHistory.pop();

    // Show the previous screen with flag to indicate this is a back navigation
    showScreen(previousScreen, true);
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
        // Normalize all whitespace characters (including non-breaking spaces, tabs, etc.) to standard spaces
    const normalizedSeedPhrase = seedPhrase.replace(/\s+/g, ' ').trim();

    // Split into words using standard spaces
    const words = normalizedSeedPhrase.split(' ');
    const wordCount = words.length;

    // Log the words for debugging
    console.log('Words:', words);

    // Validate word count (12, 15, 18, 21, 24 are the only valid lengths)
    if (![12, 15, 18, 21, 24].includes(wordCount)) {
        console.error(`Invalid seed phrase length: ${wordCount} words. Valid lengths are 12, 15, 18, 21, or 24 words.`);
        return false;
    }

    // Validate that all words exist in the wordlist
    const invalidWords = words.filter(word => !wordlist.includes(word));
    if (invalidWords.length > 0) {
        console.error(`Invalid words found in seed phrase: ${invalidWords.join(', ')}`);
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
    if (checksum !== hashBinary.slice(0, checksumBits)) {
        console.error('Invalid checksum. The seed phrase may be incorrect.');
        return false;
    }

    // If all checks pass, the seed phrase is valid
    console.log('Seed phrase is valid.');
    return true;
}
async function verifySeedAndMoveNext() {
    try {
        // Await the result of the async function
        var isValid = await verifyBip39SeedPhrase(seedPhraseField.value, words);
        if (isValid) {
            privateKeyField.value = decimalStringToHex(wordsToIndices(seedPhraseField.value));
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

    // Initialize or load the nonce for the site
    if (!nonces[siteField.value]) {
        alert("A password for a new site is being created.")
        localStoredData["users"][userOrMailField.value][siteField.value] = 0;
        nonces = localStoredData["users"][userOrMailField.value]
        console.log(`Initialized nonce for site: ${siteField.value} el nonce es: ${nonces[siteField.value]}`);
    } else {
        console.log(`Loaded nonce for site: ${siteField.value} = ${nonces[siteField.value]}`);
    }

    console.log(localStoredData)

    /*
    prepare all the verification processes to ensure proper data input
    */
    const concatenado = privateKeyField.value + "/" + userOrMailField.value + "/" + siteField.value + "/" + nonceField.value ;
    console.log(concatenado)

        const entropiaContraseña = hash(concatenado).substring(0, 16);
        passwordField.value = 'PASS' + entropiaContraseña + '249+';
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
        newSeedPhraseField.value = mnemonic
        privateKeyField.value = decimalStringToHex(wordsToIndices(mnemonic));
        return;
    })();
    // Example usage generateValidMnemonic().then(mnemonic => console.log("Generated Mnemonic:", mnemonic)).catch(console.error);

}

function updateNonceFromLocalStorage() {
    const privateKey = document.getElementById("privateKeyField").value;
    const userOrMail = document.getElementById("userOrMailField").value;
    const site = document.getElementById("siteField").value;
    const nonceField = document.getElementById("nonceField");

    if (!privateKey || !userOrMail || !site) {
        console.log("no private key, user or site")
        return;
    }
    if(localStoredStatus==="loaded"){
        try{
            nonceField.value = localStoredData["users"][userOrMail][site];
        }
        catch (error){
            console.log("no nonce on the encrypted local storage")
        }
    }
    console.log(localStoredData)
}

function incrementSiteNonce() {
    const userOrMail = document.getElementById("userOrMailField").value;
    const site = document.getElementById("siteField").value;
    const nonceField = document.getElementById("nonceField");
    if (!userOrMail || !site){
    alert("there is no site or user value")
        return
}
    // agregar error al incrementar nonce, primero crear primera contraseña
    let nonce = parseInt(nonceField.value, 10) || 0;
    nonce++;
    nonceField.value = nonce;
    localStoredData["users"][userOrMail][site] = nonce;
}

function decrementSiteNonce() {
    const userOrMail = document.getElementById("userOrMailField").value;
    const site = document.getElementById("siteField");
    const nonceField = document.getElementById("nonceField");
    if (!userOrMail || !site) {
        alert("there is no site or user value")
        return
    }
    let nonce = parseInt(nonceField.value, 10) || 0;
    if (nonce > 0) {
        nonce--;
        nonceField.value = nonce;
        localStoredData["users"][userOrMail][site] = nonce
    }
}


document.getElementById("siteField").addEventListener("input", updateNonceFromLocalStorage);
// Keydown event listener to handle Enter key
document.addEventListener("keydown", function (event) {
    if (event.key === "Enter") {
        event.preventDefault();
        switch (currentScreenId) {
            case "recoverScreen":
                verifySeedAndMoveNext();
                break;
            case "verifySeedBackUpScreen":
                verifySeedPhrase();
                break;
            // Add more cases for additional screens
            default:
                console.log("Enter pressed on screen:", currentScreenId);
                break;
        }
    }
});

// Function to get random unique indices
function getRandomIndices(max, count) {
    const indices = new Set();
    while (indices.size < count) {
        indices.add(Math.floor(Math.random() * max));
    }
    return Array.from(indices);
}

// Function to set up the verification screen
function setupVerificationScreen() {
    const wordPrompts = document.getElementById("wordPrompts");
    wordPrompts.innerHTML = "";

    const newSeedPhraseField = document.getElementById("newSeedPhraseField");
    // Split on whitespace and remove any extra spaces
    const words = newSeedPhraseField.value.trim().split(/\s+/);

    // Choose 4 random unique indices from the seed words
    const randomIndices = getRandomIndices(words.length, 4);

    randomIndices.forEach((index) => {
        const prompt = document.createElement("div");
        prompt.className = "input-group";
        prompt.innerHTML = `
          <label class="input-label">Word #${index + 1}:</label>
          <input type="text" class="input-field" data-index="${index}">
      `;
        wordPrompts.appendChild(prompt);
    });
}

// Function to verify the seed phrase
function verifySeedPhrase() {
    const newSeedPhraseField = document.getElementById("newSeedPhraseField");
    const words = newSeedPhraseField.value.trim().split(/\s+/);

    // Only select inputs within the verification screen
    const wordInputs = document.querySelectorAll(
        "#verifySeedBackUpScreen .input-field"
    );
    let allCorrect = true;

    wordInputs.forEach((input) => {
        const index = parseInt(input.dataset.index, 10);
        const enteredWord = input.value.trim().toLowerCase();

        // Safety check: if the index is invalid
        if (index >= words.length || !words[index]) {
            alert("Verification system error. Please regenerate seed phrase.");
            allCorrect = false;
            return;
        }

        const correctWord = words[index].toLowerCase();

        if (enteredWord !== correctWord) {
            allCorrect = false;
            input.style.border = "2px solid red";
        } else {
            input.style.border = "2px solid green";
        }
    });

    if (allCorrect) {
        alert("Verification successful!");
        moveToManagementScreen();
    } else {
        document.getElementById("verificationResult").textContent =
            "Verification failed. Please try again.";
    }
}

// Function called after successful verification
function moveToManagementScreen() {
    // Clear sensitive seed phrase data from the DOM
    document.getElementById("newSeedPhraseField").value = "";
    // Proceed to the next screen (e.g., wallet dashboard)
    showScreen("managementScreen");
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

function loadEncryptedData() {
    const passwordInput = document.getElementById('encryptionPassword');
    const password = passwordInput.value.trim();
    if (!password || !passwordInput) {
        alert('No password to load encrypted data, no local storage will be used.');
        return {};
    }

    try {
        const key = hash(password); // Use the hashed password to retrieve the encrypted data
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
        localStoredStatus = "loaded"
        alert('Data loaded successfully.');
        showScreen("managementScreen")
        return localStoredData; // Parse the JSON string back into an object
    } catch (error) {
        console.error('Error during decryption or parsing:', error.message);
        alert('Failed to decrypt. Invalid password or corrupted data.');
    }
}

function saveEncryptedData() {
    const password1 = document.getElementById('encryptPass1').value;
    const password2 = document.getElementById('encryptPass2').value;
    if(password1!==password2) {
        alert('Password do not match.');
        return;
    }
    if (!password1) {
        alert('Please enter a password.');
        return;
    }

    if (Object.keys(localStoredData).length === 0) {
        alert('There is no data to save.');
        return;
    }
    if(localStoredStatus === "loaded"){
        alert("Overwriting encrypted storage, press again to confirm.")
        localStoredStatus = ""
        return;
    }

    localStoredData["privateKey"] = privateKeyField.value

    const key = hash(password1); // Use the hashed password as the dictionary key
    const encrypted = CryptoJS.AES.encrypt(JSON.stringify(localStoredData), password1).toString(); // Encrypt with the raw password

    // Load existing dictionary from localStorage
    const existingData = loadDictionary("encryptedDataStorage") || {};
    existingData[key] = encrypted; // Save the encrypted data using the hashed password as the key
    saveDictionary("encryptedDataStorage", existingData); // Save back to localStorage
    console.log('Data saved with hashed key:', key);
    console.log('Data:', existingData[key]);
    alert("Data encrypted succesfully")
    refreshPage()
}

function refreshPage() {
    location.reload();
}
