package com.example.passwordmanager

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

object SecureStorage {
    private const val PREF_FILE = "secure_data"
    private const val KEY_DATA = "encrypted_json"

    private fun prefs(context: Context) = EncryptedSharedPreferences.create(
        context,
        PREF_FILE,
        masterKey(context),
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    private fun masterKey(context: Context): MasterKey {
        return MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .setUserAuthenticationRequired(true, 0)
            .build()
    }

    fun save(context: Context, data: String) {
        prefs(context).edit().putString(KEY_DATA, data).apply()
    }

    fun load(context: Context): String? {
        return prefs(context).getString(KEY_DATA, null)
    }
}
