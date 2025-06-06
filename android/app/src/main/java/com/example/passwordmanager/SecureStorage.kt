package com.example.passwordmanager

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

object SecureStorage {
    private const val PREFS_NAME = "secure_data"
    private const val KEY_PRIVATE = "private_key"

    fun prefs(context: Context) = EncryptedSharedPreferences.create(
        context,
        PREFS_NAME,
        MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    fun saveKey(context: Context, hex: String, onSuccess: () -> Unit) {
        BiometricHelper.authenticate(context) {
            prefs(context).edit().putString(KEY_PRIVATE, hex).apply()
            onSuccess()
        }
    }

    fun loadKey(context: Context, onResult: (String?) -> Unit) {
        BiometricHelper.authenticate(context) {
            onResult(prefs(context).getString(KEY_PRIVATE, null))
        }
    }

    fun hasKey(context: Context): Boolean = prefs(context).contains(KEY_PRIVATE)
}
