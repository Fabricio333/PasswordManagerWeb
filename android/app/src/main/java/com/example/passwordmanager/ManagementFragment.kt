package com.example.passwordmanager

import android.content.Context
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import androidx.fragment.app.Fragment
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

class ManagementFragment : Fragment() {

    companion object {
        private const val ARG_MODE = "mode"
        fun newCreate(): ManagementFragment = ManagementFragment().apply {
            arguments = Bundle().apply { putString(ARG_MODE, "create") }
        }
        fun newImport(): ManagementFragment = ManagementFragment().apply {
            arguments = Bundle().apply { putString(ARG_MODE, "import") }
        }
    }

    private lateinit var userField: EditText
    private lateinit var siteField: EditText
    private lateinit var nonceField: EditText
    private lateinit var passwordField: EditText

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        val view = inflater.inflate(R.layout.fragment_management, container, false)
        userField = view.findViewById(R.id.userField)
        siteField = view.findViewById(R.id.siteField)
        nonceField = view.findViewById(R.id.nonceField)
        passwordField = view.findViewById(R.id.passwordField)

        val mode = arguments?.getString(ARG_MODE)
        if (mode == "create") {
            val mnemonic = PasswordUtils.generateMnemonic()
            savePrivateKey(wordsToPrivateKey(mnemonic))
        } else if (mode == "import") {
            // In a real app prompt user to input mnemonic
        }

        view.findViewById<Button>(R.id.showPasswordButton).setOnClickListener {
            val privateKey = loadPrivateKey() ?: return@setOnClickListener
            val pass = PasswordUtils.derivePassword(
                privateKey,
                userField.text.toString(),
                siteField.text.toString(),
                nonceField.text.toString()
            )
            passwordField.setText(pass)
        }
        return view
    }

    private fun wordsToPrivateKey(words: String): String {
        val dec = PasswordUtils.wordsToIndices(words)
        return PasswordUtils.decimalStringToHex(dec)
    }

    private fun savePrivateKey(hex: String) {
        BiometricHelper.authenticate(requireActivity()) {
            val prefs = securePrefs(requireContext())
            prefs.edit().putString("private_key", hex).apply()
        }
    }

    private fun loadPrivateKey(): String? {
        var result: String? = null
        BiometricHelper.authenticate(requireActivity()) {
            result = securePrefs(requireContext()).getString("private_key", null)
        }
        return result
    }

    private fun securePrefs(context: Context) = EncryptedSharedPreferences.create(
        context,
        "secure_data",
        MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )
}
