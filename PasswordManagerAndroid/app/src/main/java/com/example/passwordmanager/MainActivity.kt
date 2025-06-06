package com.example.passwordmanager

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.compose.foundation.layout.*
import androidx.compose.material.Button
import androidx.compose.material.MaterialTheme
import androidx.compose.material.OutlinedTextField
import androidx.compose.material.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.Alignment
import androidx.compose.ui.unit.dp
import com.example.passwordmanager.R
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
    private fun authenticate(onResult: (Boolean) -> Unit) {
        val executor = ContextCompat.getMainExecutor(this)
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Unlock SecurePass")
            .setSubtitle("Use fingerprint or device PIN")
            .setAllowedAuthenticators(
                BiometricManager.Authenticators.BIOMETRIC_STRONG or
                    BiometricManager.Authenticators.DEVICE_CREDENTIAL
            ).build()
        val prompt = BiometricPrompt(this, executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    onResult(true)
                }
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    onResult(false)
                }
            })
        prompt.authenticate(promptInfo)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            var unlocked by remember { mutableStateOf(false) }
            MaterialTheme {
                if (unlocked) {
                    PasswordManagerScreen()
                } else {
                    UnlockScreen { authenticate { unlocked = it } }
                }
            }
        }
    }
}

@Composable
fun UnlockScreen(onUnlock: () -> Unit) {
    Column(modifier = Modifier.fillMaxSize(), verticalArrangement = Arrangement.Center, horizontalAlignment = Alignment.CenterHorizontally) {
        Button(onClick = onUnlock) {
            Text(stringResource(R.string.unlock_button))
        }
    }
}

@Composable
fun PasswordManagerScreen() {
    val context = LocalContext.current
    var seed by remember { mutableStateOf("") }
    var user by remember { mutableStateOf("") }
    var site by remember { mutableStateOf("") }
    var nonce by remember { mutableStateOf(0) }
    var password by remember { mutableStateOf("") }
    val scope = rememberCoroutineScope()

    Column(modifier = Modifier.padding(16.dp)) {
        OutlinedTextField(value = seed, onValueChange = { seed = it }, label = { Text("Seed Phrase") })
        Spacer(Modifier.height(8.dp))
        Button(onClick = {
            scope.launch {
                val key = PasswordManager.privateKeyFromMnemonic(context, seed)
                PasswordManager.savePrivateKey(context, key)
            }
        }) { Text(stringResource(R.string.save_seed)) }
        Spacer(Modifier.height(16.dp))
        OutlinedTextField(value = user, onValueChange = { user = it }, label = { Text("User / Email") })
        OutlinedTextField(value = site, onValueChange = { site = it }, label = { Text("Site") })
        Row {
            Button(onClick = { if (nonce > 0) nonce-- }) { Text("-") }
            Text("  $nonce  ")
            Button(onClick = { nonce++ }) { Text("+") }
        }
        Spacer(Modifier.height(8.dp))
        Button(onClick = {
            scope.launch {
                val key = PasswordManager.loadPrivateKey(context) ?: return@launch
                password = PasswordManager.derivePassword(key, user, site, nonce)
                PasswordManager.setNonce(context, user, site, nonce)
            }
        }) { Text(stringResource(R.string.generate_password)) }
        Spacer(Modifier.height(8.dp))
        Text(password)
    }
}
