# Android Wrapper for PasswordManagerWeb

This is a minimal Android project that loads the existing web application in a `WebView` after authenticating the user using the device's fingerprint (BiometricPrompt API). The private key can be stored encrypted and unlocked only after successful biometric authentication.

## Building

Use Android Studio to open the `android` directory and build the project.

### GitHub Release

When you push a tag matching `v*` to GitHub or run the workflow manually, GitHub
Actions builds the release APK automatically. The resulting file is attached to
the GitHub release, so you can download the ready-to-install APK directly from
the "Releases" page.
