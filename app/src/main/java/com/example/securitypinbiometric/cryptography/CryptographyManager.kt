package com.example.securityauth.cryptography

import javax.crypto.Cipher
import javax.crypto.SecretKey

interface CryptographyManager {

    fun getInitializedCipherForEncryption(alias: String): Cipher

    fun getInitializedCipherForDecryption(alias: String, initializationVector: ByteArray): Cipher

    fun getInitializedCipherForDecryption(secretKey: SecretKey, initializationVector: ByteArray): Cipher

    fun getInitializedCipherForEncryption(secretKey: SecretKey): Cipher

    fun encryptData(plaintext: String, cipher: Cipher): CiphertextWrapper

    fun encryptData(plaintext: ByteArray, cipher: Cipher): CiphertextWrapper

    fun decryptData(ciphertext: ByteArray, cipher: Cipher): ByteArray
}