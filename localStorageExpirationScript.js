// Function to set data with expiration
function setWithExpiry(key, value, ttl) {
    const now = new Date();
    const item = {
        value: value, // The actual data
        expiry: now.getTime() + ttl // Expiration time in milliseconds
    };
    localStorage.setItem(key, JSON.stringify(item));
}

// Function to get data with expiration check
function getWithExpiry(key) {
    const itemStr = localStorage.getItem(key);

    // If the item does not exist, return null
    if (!itemStr) {
        return null;
    }

    const item = JSON.parse(itemStr);
    const now = new Date();

    // Check if the item is expired
    if (now.getTime() > item.expiry) {
        localStorage.removeItem(key); // Remove the item from storage
        return null; // Indicate that the item has expired
    }

    return item.value; // Return the valid data
}

// Example usage
setWithExpiry('example', { foo: 'bar' }, 60000); // Expires in 1 minute (60000 ms)

const data = getWithExpiry('example');
if (data) {
    console.log('Data:', data);
} else {
    console.log('Data has expired or does not exist.');
}