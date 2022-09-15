package com.example.securityauth.app

import android.app.Application
import android.hardware.biometrics.BiometricManager
import androidx.security.crypto.EncryptedSharedPreferences

class App : Application() {

    val encryptedStorage by lazy {
        EncryptedSharedPreferences.create(
            "main_storage",
            "main_storage_key",
            this,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    val biometricManager by lazy { androidx.biometric.BiometricManager.from(this) }
}
