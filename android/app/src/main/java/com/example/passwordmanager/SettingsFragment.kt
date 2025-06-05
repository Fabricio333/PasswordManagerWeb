package com.example.passwordmanager

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.Toast
import androidx.fragment.app.Fragment

class SettingsFragment : Fragment() {
    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        val view = inflater.inflate(R.layout.fragment_settings, container, false)
        val edit = view.findViewById<EditText>(R.id.data_edit)
        val button = view.findViewById<Button>(R.id.save_button)
        edit.setText(SecureStorage.loadData(requireContext()))
        button.setOnClickListener {
            SecureStorage.saveData(requireContext(), edit.text.toString())
            Toast.makeText(requireContext(), "Data saved", Toast.LENGTH_SHORT).show()
        }
        return view
    }
}
