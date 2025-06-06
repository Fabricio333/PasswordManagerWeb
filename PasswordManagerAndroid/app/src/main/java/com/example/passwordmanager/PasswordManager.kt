package com.example.passwordmanager

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.security.MessageDigest
import kotlin.random.Random

object PasswordManager {

    private const val PREFERENCES_FILE = "pm_storage"
    private const val PRIVATE_KEY_KEY = "private_key"
    private const val NONCES_KEY_PREFIX = "nonce_"

    fun savePrivateKey(context: Context, key: String) {
        val prefs = getPrefs(context)
        prefs.edit().putString(PRIVATE_KEY_KEY, key).apply()
    }

    fun loadPrivateKey(context: Context): String? {
        return getPrefs(context).getString(PRIVATE_KEY_KEY, null)
    }

    fun getNonce(context: Context, user: String, site: String): Int {
        val key = NONCES_KEY_PREFIX + user + "_" + site
        return getPrefs(context).getInt(key, 0)
    }

    fun setNonce(context: Context, user: String, site: String, nonce: Int) {
        val key = NONCES_KEY_PREFIX + user + "_" + site
        getPrefs(context).edit().putInt(key, nonce).apply()
    }

    fun hash(text: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val bytes = digest.digest(text.toByteArray())
        return bytes.joinToString("") { "%02x".format(it) }
    }

    fun derivePassword(privateKey: String, user: String, site: String, nonce: Int): String {
        val concat = "$privateKey/$user/$site/$nonce"
        val entropy = hash(concat).substring(0, 16)
        return "PASS" + entropy + "249+"
    }

    suspend fun generateMnemonic(context: Context): String {
        val wordList = loadWordList(context)
        val entropy = Random.nextBytes(16)
        val binary = entropy.joinToString("") { it.toUByte().toString(2).padStart(8, '0') }
        val checksum = hash(entropy).substring(0, 2) // 16 bits checksum
        val combined = binary + checksum
        val words = combined.chunked(11).map { chunk ->
            val idx = chunk.toInt(2)
            wordList[idx]
        }
        return words.joinToString(" ")
    }

    suspend fun verifyMnemonic(context: Context, phrase: String): Boolean {
        val wordList = loadWordList(context)
        val cleaned = phrase.trim().split(/\s+/.toRegex())
        if (cleaned.size !in listOf(12, 15, 18, 21, 24)) return false
        if (cleaned.any { !wordList.contains(it) }) return false
        return true // simplified
    }

    fun wordsToIndices(phrase: String, list: List<String>): String {
        return phrase.trim().split(" ").joinToString("") { word ->
            val idx = list.indexOf(word)
            idx.toString().padStart(4, '0')
        }
    }

    fun decimalStringToHex(decimal: String): String {
        val big = decimal.toBigInteger()
        return big.toString(16)
    }

    suspend fun privateKeyFromMnemonic(context: Context, phrase: String): String {
        val wordList = loadWordList(context)
        val indices = wordsToIndices(phrase, wordList)
        return decimalStringToHex(indices)
    }

    private suspend fun loadWordList(context: Context): List<String> {
        return context.assets.open("bip39_words.txt").bufferedReader().use { it.readLines() }
    }

    private fun hash(bytes: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val bytesHashed = digest.digest(bytes)
        return bytesHashed.joinToString("") { "%02x".format(it) }
    }

    private fun getPrefs(context: Context) =
        EncryptedSharedPreferences.create(
            context,
            PREFERENCES_FILE,
            MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
}
