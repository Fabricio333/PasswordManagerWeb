package com.example.passwordmanager

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

object SecureStorage {
    private const val PREF_NAME = "vault_data"
    private const val KEY_DATA = "stored_data"

    private fun prefs(context: Context) =
        EncryptedSharedPreferences.create(
            context,
            PREF_NAME,
            MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build(),
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )

    fun loadData(context: Context): String {
        return prefs(context).getString(KEY_DATA, "") ?: ""
    }

    fun saveData(context: Context, data: String) {
        prefs(context).edit().putString(KEY_DATA, data).apply()
    }
}
