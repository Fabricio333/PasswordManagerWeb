package com.example.passwordmanager

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricPrompt
import androidx.biometric.BiometricManager
import androidx.core.content.ContextCompat
import android.webkit.WebView
import android.webkit.WebViewClient

class MainActivity : AppCompatActivity() {
    private lateinit var webView: WebView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        webView = WebView(this)
        webView.settings.javaScriptEnabled = true
        webView.settings.domStorageEnabled = true
        webView.settings.allowFileAccess = true
        webView.webViewClient = WebViewClient()
        setContentView(webView)

        authenticateAndLoad()
    }

    private fun authenticateAndLoad() {
        val biometricManager = BiometricManager.from(this)
        val canAuth = biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)

        if (canAuth == BiometricManager.BIOMETRIC_SUCCESS) {
            val executor = ContextCompat.getMainExecutor(this)
            val biometricPrompt = BiometricPrompt(this, executor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        super.onAuthenticationSucceeded(result)
                        loadWebApp()
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        super.onAuthenticationError(errorCode, errString)
                        loadWebApp()
                    }
                })

            val promptInfo = BiometricPrompt.PromptInfo.Builder()
                .setTitle("Unlock")
                .setSubtitle("Authenticate to decrypt your private key")
                .setNegativeButtonText("Cancel")
                .build()

            biometricPrompt.authenticate(promptInfo)
        } else {
            loadWebApp()
        }
    }

    private fun loadWebApp() {
        webView.loadUrl("file:///android_asset/www/index.html")
    }
}
