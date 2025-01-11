var isVisible = false;

function toggleSettings() {
    var container = document.getElementById('toggle-container');
    if (isVisible) {
        container.style.display = 'none';
    } else {
        container.style.display = 'block';
    }
    isVisible = !isVisible;
}