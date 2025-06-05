package com.example.passwordmanager

import android.content.Context
import android.webkit.JavascriptInterface

class WebAppInterface(private val context: Context) {
    @JavascriptInterface
    fun saveEncryptedData(data: String) {
        SecureStorage.save(context, data)
    }

    @JavascriptInterface
    fun loadEncryptedData(): String? {
        return SecureStorage.load(context)
    }
}
