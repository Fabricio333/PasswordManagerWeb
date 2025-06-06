package com.example.passwordmanager

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import androidx.fragment.app.Fragment
import com.google.android.material.button.MaterialButton

class ImportFragment : Fragment() {
    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        val view = inflater.inflate(R.layout.fragment_import, container, false)
        val input = view.findViewById<EditText>(R.id.mnemonicInput)
        view.findViewById<MaterialButton>(R.id.confirmImportButton).setOnClickListener {
            val words = input.text.toString()
            val key = PasswordUtils.decimalStringToHex(
                PasswordUtils.wordsToIndices(words)
            )
            SecureStorage.saveKey(requireContext(), key) {
                parentFragmentManager.popBackStack()
                parentFragmentManager.beginTransaction()
                    .replace(R.id.fragment_container, DeriveFragment())
                    .commit()
            }
        }
        return view
    }
}
