package com.example.securitypinbiometric.model

import androidx.biometric.BiometricPrompt

data class BiometricParams(
    val promptInfo: BiometricPrompt.PromptInfo,
    val cryptoObject: BiometricPrompt.CryptoObject,
    val onAuthSuccess: (BiometricPrompt.AuthenticationResult) -> Unit
)
