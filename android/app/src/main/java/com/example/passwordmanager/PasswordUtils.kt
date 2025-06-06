package com.example.passwordmanager

import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom

object PasswordUtils {
    fun generateMnemonic(): String {
        val random = SecureRandom()
        return (1..12).joinToString(" ") { BIP39Words.words[random.nextInt(BIP39Words.words.size)] }
    }

    fun wordsToIndices(words: String): String {
        return words.trim().split("\s+").joinToString("") { word ->
            val index = BIP39Words.words.indexOf(word)
            require(index >= 0) { "Word $word not found" }
            index.toString().padStart(4, '0')
        }
    }

    fun decimalStringToHex(decimal: String): String {
        require(decimal.all { it.isDigit() }) { "Invalid decimal input" }
        return BigInteger(decimal).toString(16)
    }

    private fun hash(text: String): String {
        val md = MessageDigest.getInstance("SHA-256")
        val bytes = md.digest(text.toByteArray())
        return bytes.joinToString("") { "%02x".format(it) }
    }

    fun derivePassword(privateKey: String, user: String, site: String, nonce: String): String {
        val concatenated = "$privateKey/$user/$site/$nonce"
        val hashed = hash(concatenated).substring(0,16)
        return "PASS" + hashed + "249+"
    }
}
