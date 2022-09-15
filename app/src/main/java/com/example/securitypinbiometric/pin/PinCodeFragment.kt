package com.example.securityauth.ui.pin

import android.os.Bundle
import androidx.fragment.app.Fragment
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.appcompat.app.AlertDialog
import androidx.fragment.app.viewModels
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.coroutineScope
import androidx.lifecycle.flowWithLifecycle
import com.example.securitypinbiometric.model.BiometricParams
import com.example.securityauth.databinding.FragmentPinCodeBinding
import com.example.securityauth.utils.BiometricPromptUtils
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach

class PinCodeFragment : Fragment() {

    companion object {
        fun newInstance() = PinCodeFragment()
    }

    private val viewModel by viewModels<PinCodeViewModel>()
    private lateinit var binding: FragmentPinCodeBinding

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        binding = FragmentPinCodeBinding.inflate(layoutInflater)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        viewModel.askActivateBiometricsAuthDialogFlow.observe(viewLifecycleOwner) {
            showBiometricEnableDialog()
        }
        viewModel.showBiometricDialogFlow.observe(viewLifecycleOwner, ::showBiometricPrompt)

        binding.createPinButton.setOnClickListener {
            viewModel.onCreatePin(binding.message.text.toString())
        }
        binding.enterPinButton.setOnClickListener {
            viewModel.onPinIsValid(binding.message.text.toString())
        }
        binding.authByBiometry.setOnClickListener {
            viewModel.onAuthByBiometric()
        }
    }

    private fun showBiometricPrompt(params: BiometricParams) {
        // BiometricPrompt нужен для обработки колбэков биометрии
        val biometricPrompt = BiometricPromptUtils.createBiometricPrompt(this, params.onAuthSuccess)

        // Запускаем биометрию с созданным CryptoObject, в котором содержится наш cypher
        biometricPrompt.authenticate(params.promptInfo, params.cryptoObject)
    }

    private fun showBiometricEnableDialog() {
        AlertDialog.Builder(requireContext())
            .setMessage("Хотите ли вы активировать авторизацию по биометрии?")
            .setPositiveButton("Да") { _, _ -> viewModel.onBiometricAvailable() }
            .setNegativeButton("Нет") { _, _ ->  }
            .create()
            .show()
    }
}

fun <T> Flow<T>.observe(lifecycleOwner: LifecycleOwner, action: suspend (value: T) -> Unit = {}) {
    onEach(action)
        .flowWithLifecycle(lifecycleOwner.lifecycle, Lifecycle.State.STARTED)
        .launchIn(lifecycleOwner.lifecycle.coroutineScope)
}