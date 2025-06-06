package com.example.passwordmanager

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.fragment.app.Fragment
import com.google.android.material.button.MaterialButton

class CreateFragment : Fragment() {
    private lateinit var words: String

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        words = PasswordUtils.generateMnemonic()
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        val view = inflater.inflate(R.layout.fragment_create, container, false)
        view.findViewById<TextView>(R.id.wordsView).text = words
        view.findViewById<MaterialButton>(R.id.confirmButton).setOnClickListener {
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
