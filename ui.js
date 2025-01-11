// Flag variable to keep track of whether settings are visible or not
let isVisible = false;

/**
 * Toggles visibility of settings container.
 */
function toggleSettings() {
    // Get reference to #toggle-container element
    const container = document.getElementById('toggle-container');

    // If settings are currently visible, hide them; otherwise show them
    if (isVisible) {
        container.style.display = 'none';
    } else {
        container.style.display = 'block';
    }

    // Toggle the flag variable to remember new state
    isVisible = !isVisible;
}

