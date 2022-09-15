package com.example.securityauth.cryptography

data class CiphertextWrapper(
    val ciphertext: ByteArray,
    val initializationVector: ByteArray
)