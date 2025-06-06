package com.example.passwordmanager

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import androidx.fragment.app.Fragment
import com.google.android.material.button.MaterialButton

class DeriveFragment : Fragment() {
    private lateinit var userField: EditText
    private lateinit var siteField: EditText
    private lateinit var nonceField: EditText
    private lateinit var passwordField: EditText

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        val view = inflater.inflate(R.layout.fragment_derive, container, false)
        userField = view.findViewById(R.id.userField)
        siteField = view.findViewById(R.id.siteField)
        nonceField = view.findViewById(R.id.nonceField)
        passwordField = view.findViewById(R.id.passwordField)

        view.findViewById<MaterialButton>(R.id.showPasswordButton).setOnClickListener {
            SecureStorage.loadKey(requireContext()) { key ->
                key ?: return@loadKey
                val pass = PasswordUtils.derivePassword(
                    key,
                    userField.text.toString(),
                    siteField.text.toString(),
                    nonceField.text.toString()
                )
                passwordField.setText(pass)
            }
        }
        return view
    }
}
