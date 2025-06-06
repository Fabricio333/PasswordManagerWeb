package com.example.passwordmanager

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.material.Button
import androidx.compose.material.MaterialTheme
import androidx.compose.material.OutlinedTextField
import androidx.compose.material.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                PasswordManagerScreen()
            }
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
        }) { Text("Save Seed") }
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
        }) { Text("Generate") }
        Spacer(Modifier.height(8.dp))
        Text(password)
    }
}
