package com.example.passwordmanager

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import androidx.fragment.app.Fragment

class SetupFragment : Fragment() {
    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        if (SecureStorage.hasKey(requireContext())) {
            parentFragmentManager.beginTransaction()
                .replace(R.id.fragment_container, DeriveFragment())
                .commit()
        }
        val view = inflater.inflate(R.layout.fragment_setup, container, false)
        view.findViewById<Button>(R.id.createKeyButton).setOnClickListener {
            parentFragmentManager.beginTransaction()
                .replace(R.id.fragment_container, CreateFragment())
                .addToBackStack(null)
                .commit()
        }
        view.findViewById<Button>(R.id.importKeyButton).setOnClickListener {
            parentFragmentManager.beginTransaction()
                .replace(R.id.fragment_container, ImportFragment())
                .addToBackStack(null)
                .commit()
        }
        return view
    }
}
