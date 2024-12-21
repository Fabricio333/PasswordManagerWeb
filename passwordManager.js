import words from words

var password = document.getElementById('password');
var site = document.getElementById('site')
var entropyInput = document.getElementById('entropyInput')
var nonce = document.getElementById('nonce')
var lastResult, countResults = 0;

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

}

function manualEntropyInput(){
    entropyInput.value = document.getElementById('entropyManualInput').value
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

    // Check if the site input is empty
    if (!site.value) {
        password.value = 'The site input is empty';
        return;
    }
    // Check if the entropy input is empty
    if (!entropyInput.value) {
        password.value = 'The entropy input is empty';
        return;
    }
    // Initialize or load the nonce for the site
    if (!nonces[site.value]) {
        nonces[site.value] = 0;
        console.log(`Initialized nonce for site: ${site.value} el nonce es: ${nonces[site.value]}`);
        saveDictionary('nonces', nonces);
    } else {
        console.log(`Loaded nonce for site: ${site.value} = ${nonces[site.value]}`);
    }

    nonce.value = nonces[site.value];

    // Generate password
    const concatenado = entropyInput.value + '@' + site.value + nonce.value;
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
    nonces = loadDictionary('nonces')
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

function copyToClipboard(where) {
    var outputText = document.getElementById(where);
    navigator.clipboard.writeText(outputText.textContent).then(function() {
        alert('Text copied to clipboard!');
    }, function() {
        alert('Failed to copy text.');
    });
}

function main(){
html5QrcodeScanner.render(onScanSuccess);
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

// Function to update a key-value pair in the dictionary
function updateDictionary(key, newKey, newValue) {
    // Load the current dictionary
    let dictionary = loadDictionary(key);

    // Update the dictionary with the new key-value pair
    dictionary[newKey] = newValue;

    // Save the updated dictionary back to localStorage
    saveDictionary(key, dictionary);
}


/*

const exampleDictionary = {
    "username": "johndoe",
    "email": "johndoe@example.com",
    "age": 30,
    "location": "New York"
};
saveDictionary("PruebaStorage",exampleDictionary)

const prueba = loadDictionary("PruebaStorage")

console.log(prueba)

// Example usage:

// Load the dictionary (if it exists)
let dictionary = loadDictionary('myDictionary');
console.log('Loaded dictionary:', dictionary);

// Update the dictionary with a new key-value pair
updateDictionary('myDictionary', 'newKey', 'newValue');

// Verify the update by loading the dictionary again
dictionary = loadDictionary('myDictionary');
console.log('Updated dictionary:', dictionary);



rotatory dayly password or whatever hahah

seedqr is just the number of word with 4 digits 25x25

*/

main()