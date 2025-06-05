# Android Wrapper for PasswordManagerWeb

This is a minimal Android project that loads the existing web application in a `WebView` after authenticating the user using the device's fingerprint (BiometricPrompt API). The private key can be stored encrypted and unlocked only after successful biometric authentication.

## Building

1. Install [Android Studio](https://developer.android.com/studio) and make sure the Android SDK is set up.
2. Start Android Studio and choose **File → Open**. Select the `android` folder from this repository.
3. Let Gradle download dependencies and finish syncing the project.
4. Choose **Build → Build APK(s)**. The resulting APK is written to `app/build/outputs/apk/release`.
5. You can install this APK on a device or emulator for testing.

### GitHub Release

When you push a tag matching `v*` to GitHub or run the workflow manually, GitHub
Actions builds the release APK automatically. The resulting file is attached to
the GitHub release, so you can download the ready-to-install APK directly from
the "Releases" page.
