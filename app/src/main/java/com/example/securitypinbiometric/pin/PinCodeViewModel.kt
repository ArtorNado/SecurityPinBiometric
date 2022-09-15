package com.example.securityauth.ui.pin

import android.app.Application
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricPrompt
import androidx.core.content.edit
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.securitypinbiometric.model.BiometricParams
import com.example.securityauth.app.App
import com.example.securityauth.cryptography.CiphertextWrapper
import com.example.securityauth.cryptography.CryptographyManager
import com.example.securityauth.cryptography.CryptographyManagerImpl
import com.example.securityauth.utils.BiometricPromptUtils
import com.example.securityauth.utils.Pbkdf2Factory
import com.example.securityauth.utils.Salt
import com.example.securityauth.utils.SampleAppUser
import com.example.securityauth.utils.StorageKey
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.launch
import java.lang.Exception
import java.nio.charset.Charset
import java.security.GeneralSecurityException
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

class PinCodeViewModel(application: Application) : AndroidViewModel(application) {

    private val cryptographyManager: CryptographyManager = CryptographyManagerImpl()
    private val biometricManager by lazy(LazyThreadSafetyMode.NONE) { getApplication<App>().biometricManager }
    private val preferences by lazy(LazyThreadSafetyMode.NONE) { getApplication<App>().encryptedStorage }
    private var secretKey: SecretKey? = null

    private val _showBiometricAuthDialogFlow = MutableSharedFlow<BiometricParams>()
    val showBiometricDialogFlow = _showBiometricAuthDialogFlow.asSharedFlow()

    private val _askActivateBiometricsAuthDialogFlow = MutableSharedFlow<Unit>()
    val askActivateBiometricsAuthDialogFlow = _askActivateBiometricsAuthDialogFlow.asSharedFlow()

    fun onCreatePin(pin: String) {
        viewModelScope.launch {
            // генерируем соль
            val salt = Salt.generate()
            // создаем SecretKey на основе ключа и соли
            secretKey = createSecretKey(pin, salt)

            secretKey?.let {
                // шифруем полученный с сервера токен
                val encryptedToken = encryptToken(SampleAppUser.fakeToken, it)

                // сохраняем зашифрованный токен и соль
                preferences.edit {
                    putString(
                        StorageKey.TOKEN,
                        Base64.encodeToString(encryptedToken.ciphertext, Base64.DEFAULT)
                    )
                    putString(
                        StorageKey.TOKEN_IV,
                        Base64.encodeToString(encryptedToken.initializationVector, Base64.DEFAULT)
                    )
                    putString(StorageKey.SALT, Base64.encodeToString(salt, Base64.DEFAULT))
                }
            }

            // после создания пин кода спрашиваем у пользователя, хочет ли он включить
            // авторизацию по биометрии
            askShowBiometricAuthIfAvailable()
        }
    }

    fun onPinIsValid(pin: String): Boolean {
        val salt = Base64.decode(preferences.getString(StorageKey.SALT, null), Base64.DEFAULT)
        // создаем секретный ключ на основе соли и введенного пользователем пин кода
        val secretKey = createSecretKey(pin, salt)

        val token = try {
            val encryptedToken =
                Base64.decode(preferences.getString(StorageKey.TOKEN, null), Base64.DEFAULT)

            val encryptedTokenIV =
                Base64.decode(preferences.getString(StorageKey.TOKEN_IV, null), Base64.DEFAULT)

            // инициализируем Cipher с полученным по введенному пин коду и соли ключу, и iv токена
            val cipher =
                cryptographyManager.getInitializedCipherForDecryption(secretKey, encryptedTokenIV)

            // Пытаемся расшифровать данные. Если пинк код был введен верный, то секретный ключ
            // будет соответствовать тому, что использовался при шифровании токена.
            // Иначе мы получим ошибку.
            decryptToken(encryptedToken, cipher)
        } catch (e: Exception) {
            Log.e("Decrypt exception -", e.toString())
            null
        }

        Log.d("Decrypted token - ", token.toString())
        return !token.isNullOrEmpty()
    }

    fun onBiometricAvailable() {
        viewModelScope.launch {
            // Создаем Cipher, который будет ипользоваться для шифрования данных после успешного
            // прохождения биометрии.
            // Благодаря защищенному секретному ключу (setUserAuthenticationRequired(true)),
            // Cipher можно будет исполльзовать только после успешного прохождения биометрии.
            val cipher = cryptographyManager.getInitializedCipherForEncryption("biometric_alias")
            // Обертка для нашего cipher
            val cryptoObject = BiometricPrompt.CryptoObject(cipher)
            // Создаем диалоговое окно для прохождения биометрии
            val biometricPrompt = BiometricPromptUtils.createPromptInfo()

            val biometricParams = BiometricParams(
                promptInfo = biometricPrompt,
                cryptoObject = cryptoObject,
                // указываем, что будет выполнятся в случае успешного прохождения биометрии
                onAuthSuccess = ::encryptSecretKey
            )

            _showBiometricAuthDialogFlow.emit(biometricParams)
        }
    }

    fun onAuthByBiometric() {
        if (preferences.contains(StorageKey.KEY) &&
            biometricManager.canAuthenticate(BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS
        ) {
            viewModelScope.launch {
                val biometricPrompt = BiometricPromptUtils.createPromptInfo()
                val cipher =
                    cryptographyManager.getInitializedCipherForDecryption(
                        "biometric_alias",
                        Base64.decode(preferences.getString(StorageKey.KEY_IV, null), Base64.DEFAULT)
                    )
                val cryptoObject = BiometricPrompt.CryptoObject(cipher)

                val biometricParams = BiometricParams(
                    promptInfo = biometricPrompt,
                    cryptoObject = cryptoObject,
                    onAuthSuccess = ::decryptSecretKey
                )

                _showBiometricAuthDialogFlow.emit(biometricParams)
            }
        } else {
            // todo biometric auth not available
        }
    }

    // Из AuthenticationResult достаем наш CryptoObject, а из него Cipher.
    // Далее шифруем наш SecretKey от токена и сохраняем зашифрованный SecretKey с его IV.
    private fun encryptSecretKey(authResult: BiometricPrompt.AuthenticationResult) {
        secretKey?.let { secretKey ->
            val encryptedSecretKey = cryptographyManager.encryptData(
                secretKey.encoded,
                authResult.cryptoObject!!.cipher!!
            )

            preferences.edit {
                putString(
                    StorageKey.KEY,
                    Base64.encodeToString(encryptedSecretKey.ciphertext, Base64.DEFAULT)
                )
                putString(
                    StorageKey.KEY_IV,
                    Base64.encodeToString(encryptedSecretKey.initializationVector, Base64.DEFAULT)
                )
            }
        }
    }

    // Из AuthenticationResult достаем наш CryptoObject, а из него Cipher.
    // Далее расшифровываем наш SecretKey от токена, после чего инициализируем Cipher
    // для расшифровки самого токена и проводим расшифровку.
    private fun decryptSecretKey(authResult: BiometricPrompt.AuthenticationResult) {
        val encryptedSecretKey =
            Base64.decode(preferences.getString(StorageKey.KEY, ""), Base64.DEFAULT)

        val secretKeyEncoded = cryptographyManager.decryptData(
            encryptedSecretKey,
            authResult.cryptoObject!!.cipher!!
        )

        val secretKey = SecretKeySpec(secretKeyEncoded, KeyProperties.KEY_ALGORITHM_AES)

        val token = try {
            val encryptedToken =
                Base64.decode(preferences.getString(StorageKey.TOKEN, null), Base64.DEFAULT)

            val encryptedTokenIV =
                Base64.decode(preferences.getString(StorageKey.TOKEN_IV, null), Base64.DEFAULT)

            val cipher =
                cryptographyManager.getInitializedCipherForDecryption(secretKey, encryptedTokenIV)

            decryptToken(encryptedToken, cipher)
        } catch (e: GeneralSecurityException) {
            Log.e("Decrypt exception -", e.toString())
            null
        }
        Log.d("Decrypted token - ", token.toString())
    }

    private fun createSecretKey(pin: String, salt: ByteArray): SecretKey {
        return Pbkdf2Factory.createKey(pin.toCharArray(), salt)
    }

    private fun encryptToken(token: String, key: SecretKey): CiphertextWrapper {
        // создаем Cipher по существующему SecretKey
        val cipher = cryptographyManager.getInitializedCipherForEncryption(key)

        // Шифруем наш токен
        return cryptographyManager.encryptData(token, cipher)
    }

    private fun decryptToken(encryptedToken: ByteArray, cipher: Cipher): String {
        // дешифруем наш токен
        val encodedToken = cryptographyManager.decryptData(encryptedToken, cipher)

        // токен дешифруется ввиде ByteArray, поэтому переводим в String
        return String(encodedToken, Charset.forName("UTF-8"))
    }

    private suspend fun askShowBiometricAuthIfAvailable() {
        if (biometricManager.canAuthenticate(BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS) {
            _askActivateBiometricsAuthDialogFlow.emit(Unit)
        }
    }
}