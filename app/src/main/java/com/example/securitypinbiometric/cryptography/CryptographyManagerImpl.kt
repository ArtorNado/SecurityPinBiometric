package com.example.securityauth.cryptography

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.nio.charset.Charset
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec

class CryptographyManagerImpl: CryptographyManager {

    companion object {
        private const val KEY_SIZE = 256
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val ENCRYPTION_BLOCK_MODE = KeyProperties.BLOCK_MODE_GCM
        private const val ENCRYPTION_PADDING = KeyProperties.ENCRYPTION_PADDING_NONE
        private const val ENCRYPTION_ALGORITHM = KeyProperties.KEY_ALGORITHM_AES
    }

    override fun getInitializedCipherForEncryption(alias: String): Cipher {
        val secretKey = getOrCreateSecretKey(alias)
        val cipher = getCipher().apply {
            init(Cipher.ENCRYPT_MODE, secretKey)
        }

        return cipher
    }

    override fun getInitializedCipherForEncryption(secretKey: SecretKey): Cipher {
        val cipher = getCipher().apply {
            init(Cipher.ENCRYPT_MODE, secretKey)
        }

        return cipher
    }

    override fun getInitializedCipherForDecryption(alias: String, initializationVector: ByteArray): Cipher {
        val secretKey = getOrCreateSecretKey(alias)
        val cipher = getCipher().apply {
            init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, initializationVector))
        }

        return cipher
    }

    override fun getInitializedCipherForDecryption(secretKey: SecretKey, initializationVector: ByteArray): Cipher {
        val cipher = getCipher().apply {
            init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, initializationVector))
        }

        return cipher
    }

    override fun encryptData(plaintext: String, cipher: Cipher): CiphertextWrapper {
        val ciphertext = cipher.doFinal(plaintext.toByteArray(Charset.forName("UTF-8")))
        return CiphertextWrapper(ciphertext, cipher.iv)
    }

    override fun encryptData(plaintext: ByteArray, cipher: Cipher): CiphertextWrapper {
        val ciphertext = cipher.doFinal(plaintext)
        return CiphertextWrapper(ciphertext, cipher.iv)
    }

    override fun decryptData(ciphertext: ByteArray, cipher: Cipher): ByteArray {
        return cipher.doFinal(ciphertext)
    }

    private fun getCipher(): Cipher {
        // Получаем инстанс Cipher с указанными режимами шифрования
        val transformation = "$ENCRYPTION_ALGORITHM/$ENCRYPTION_BLOCK_MODE/$ENCRYPTION_PADDING"
        return Cipher.getInstance(transformation)
    }

    // Достаем ключ по alias из KeyStore, если же его там нет, то создаем новый
    private fun getOrCreateSecretKey(alias: String): SecretKey {
        getSecretKeyFromKeyStorageOrNull(alias)?.let { return it }

        return generateNewSecretKey(alias)
    }

    // Получаем AndroidKeyStore и загружаем его для нашего приложения.
    // В load в качестве файла передаем просто передаем null, система под коробкой загрузит данные,
    // основываясь на идентификаторе нашего приложения.
    // Если ключ по переданному alias будет найдет в хранилище, то вернем его, иначе null
    private fun getSecretKeyFromKeyStorageOrNull(alias: String): SecretKey? {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)
        val key = keyStore.getKey(alias, null)

        return if (key != null) key as SecretKey else key
    }

    private fun generateNewSecretKey(alias: String): SecretKey {
        val paramsBuilder = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
        paramsBuilder.apply {
            setBlockModes(ENCRYPTION_BLOCK_MODE)
            setEncryptionPaddings(ENCRYPTION_PADDING)
            setKeySize(KEY_SIZE)
//            setUserAuthenticationRequired(true)
            setUserAuthenticationValidityDurationSeconds(40)
        }

        val keyGenParams = paramsBuilder.build()
        // Получаем инстанс KeyGenerator для генерации ключей. В качестве параметра принимает имя
        // алгоритма шифрования, для которого создается ключ
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            ANDROID_KEYSTORE
        )
        keyGenerator.init(keyGenParams)
        return keyGenerator.generateKey()
    }
}