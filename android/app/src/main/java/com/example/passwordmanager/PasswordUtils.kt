package com.example.passwordmanager

import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

object PasswordUtils {
    fun generateMnemonic(): String {
        val random = SecureRandom()
        return (1..12).joinToString(" ") { BIP39Words.words[random.nextInt(BIP39Words.words.size)] }
    }

    fun wordsToIndices(words: String): String {
        return words.trim().split("\s+".toRegex()).joinToString("") { word ->
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

    private fun hmac(key: String, data: String): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        val spec = SecretKeySpec(key.toByteArray(), "HmacSHA256")
        mac.init(spec)
        return mac.doFinal(data.toByteArray())
    }

    fun derivePassword(privateKey: String, user: String, site: String, nonce: String): String {
        val bytes = hmac(privateKey, "$user|$site|$nonce")
        val hashed = bytes.joinToString("") { "%02x".format(it) }.substring(0,16)
        return "SPW" + hashed + "+"
    }
}
