package com.example.passwordmanager

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.Alignment
import androidx.compose.ui.platform.LocalContext
import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import com.example.passwordmanager.ui.theme.PasswordTheme
import com.example.passwordmanager.ui.theme.AlertColor
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            PasswordTheme {
                App()
            }
        }
    }
}

@Composable
fun App() {
    var screen by remember { mutableStateOf<Screen>(Screen.Splash) }
    var privateKey by remember { mutableStateOf<String?>(null) }

    val context = LocalContext.current

    LaunchedEffect(Unit) {
        // simulate splash delay
        delay(1500)
        val stored = SecureStorage.getPrivateKey(context)
        if (stored == null) screen = Screen.Setup else {
            privateKey = stored
            screen = Screen.Derive
        }
    }

    when (val s = screen) {
        Screen.Splash -> SplashScreen()
        Screen.Setup -> SetupWizard(
            onComplete = { key ->
                privateKey = key
                SecureStorage.savePrivateKey(context, key)
                screen = Screen.Derive
            }
        )
        Screen.Derive -> privateKey?.let { DeriveScreen(it, onDelete = {
            SecureStorage.clear(context)
            privateKey = null
            screen = Screen.Setup
        }) }
    }
}

sealed class Screen {
    object Splash : Screen()
    object Setup : Screen()
    object Derive : Screen()
}

@Composable
fun SplashScreen() {
    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        CircularProgressIndicator()
    }
}

@Composable
fun SetupWizard(onComplete: (String) -> Unit) {
    var seed by remember { mutableStateOf("") }
    var generated by remember { mutableStateOf(false) }
    val wordList = remember { loadWordList(LocalContext.current) }
    Column(Modifier.padding(16.dp)) {
        if (!generated) {
            Text("Import or Generate Mnemonic", style = MaterialTheme.typography.headlineSmall)
            Spacer(Modifier.height(8.dp))
            OutlinedTextField(value = seed, onValueChange = { seed = it }, label = { Text("Mnemonic") },
                modifier = Modifier.fillMaxWidth(), keyboardOptions = KeyboardOptions.Default.copy(imeAction = ImeAction.Done))
            Spacer(Modifier.height(8.dp))
            Row {
                Button(onClick = {
                    seed = generateMnemonic(wordList)
                    generated = true
                }) { Text("Generate") }
                Spacer(Modifier.width(8.dp))
                Button(onClick = {
                    if (verifyMnemonic(seed, wordList)) {
                        val hex = wordsToHex(seed, wordList)
                        onComplete(hex)
                    }
                }) { Text("Import") }
            }
        } else {
            Text("Generated mnemonic:")
            Text(seed, style = MaterialTheme.typography.bodyMedium)
            Spacer(Modifier.height(8.dp))
            Button(onClick = {
                val hex = wordsToHex(seed, wordList)
                onComplete(hex)
            }) { Text("Continue") }
        }
    }
}

@Composable
fun DeriveScreen(privateKey: String, onDelete: () -> Unit) {
    var user by remember { mutableStateOf("") }
    var site by remember { mutableStateOf("") }
    var nonce by remember { mutableStateOf("0") }
    var password by remember { mutableStateOf("") }
    Column(Modifier.padding(16.dp)) {
        Text("Derive Password", style = MaterialTheme.typography.headlineSmall)
        Spacer(Modifier.height(8.dp))
        OutlinedTextField(value = user, onValueChange = { user = it }, label = { Text("User or Email") })
        OutlinedTextField(value = site, onValueChange = { site = it }, label = { Text("Site") })
        OutlinedTextField(value = nonce, onValueChange = { nonce = it }, label = { Text("Nonce") })
        Button(onClick = {
            password = derivePassword(privateKey, user, site, nonce)
        }) { Text("Generate") }
        if (password.isNotEmpty()) {
            Text("Password: $password")
        }
        Spacer(Modifier.height(16.dp))
        Button(onClick = onDelete, colors = ButtonDefaults.buttonColors(containerColor = AlertColor)) {
            Text("Delete Local Data")
        }
    }
}

fun derivePassword(key: String, user: String, site: String, nonce: String): String {
    val concat = "$key/$user/$site/$nonce"
    val hash = sha256(concat).substring(0, 16)
    return "PASS" + hash + "249+"
}

fun sha256(text: String): String {
    val digest = MessageDigest.getInstance("SHA-256").digest(text.toByteArray())
    return digest.joinToString("") { "%02x".format(it) }
}

fun loadWordList(context: Context): List<String> {
    return context.assets.open("wordlist.txt").bufferedReader().useLines { it.toList() }
}

fun verifyMnemonic(seed: String, wordList: List<String>): Boolean {
    val words = seed.trim().split(" ")
    if (words.size !in listOf(12,15,18,21,24)) return false
    if (!words.all { wordList.contains(it) }) return false
    val totalBits = words.size * 11
    val checksumBits = totalBits % 32
    val entropyBits = totalBits - checksumBits
    val binary = words.joinToString("") { wordList.indexOf(it).toString(2).padStart(11,'0') }
    val entropy = binary.substring(0, entropyBits)
    val checksum = binary.substring(entropyBits)
    val entropyBytes = ByteArray(entropy.length/8) { idx -> Integer.parseInt(entropy.substring(idx*8,(idx+1)*8),2).toByte() }
    val hash = MessageDigest.getInstance("SHA-256").digest(entropyBytes)
    val hashBinary = hash.joinToString("") { (it.toInt() and 0xFF).toString(2).padStart(8,'0') }
    return checksum == hashBinary.substring(0, checksumBits)
}

fun generateMnemonic(wordList: List<String>): String {
    val entropy = ByteArray(16)
    SecureRandom().nextBytes(entropy)
    val hash = MessageDigest.getInstance("SHA-256").digest(entropy)
    val checksumBits = entropy.size * 8 / 32
    val entropyBinary = entropy.joinToString("") { (it.toInt() and 0xFF).toString(2).padStart(8,'0') }
    val hashBinary = hash.joinToString("") { (it.toInt() and 0xFF).toString(2).padStart(8,'0') }
    val binary = entropyBinary + hashBinary.substring(0, checksumBits)
    val result = mutableListOf<String>()
    for (i in binary.indices step 11) {
        val idx = Integer.parseInt(binary.substring(i,i+11),2)
        result.add(wordList[idx])
    }
    return result.joinToString(" ")
}

fun wordsToHex(seed: String, wordList: List<String>): String {
    val indices = seed.trim().split(" ").map { wordList.indexOf(it) }
    val decimalString = indices.joinToString("") { it.toString().padStart(4,'0') }
    return BigInteger(decimalString).toString(16)
}

object SecureStorage {
    private const val PREF = "secure"
    private const val KEY = "priv"

    fun getPrivateKey(context: Context): String? {
        val prefs = getPrefs(context)
        return prefs.getString(KEY, null)
    }

    fun savePrivateKey(context: Context, value: String) {
        val prefs = getPrefs(context)
        prefs.edit().putString(KEY, value).apply()
    }

    fun clear(context: Context) {
        getPrefs(context).edit().clear().apply()
    }

    private fun getPrefs(context: Context): SharedPreferences {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        return EncryptedSharedPreferences.create(
            context,
            PREF,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }
}
