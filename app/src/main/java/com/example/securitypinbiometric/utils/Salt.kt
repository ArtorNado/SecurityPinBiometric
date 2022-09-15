package com.example.securityauth.utils

import java.security.SecureRandom

object Salt {

    fun generate(lengthByte: Int = 32): ByteArray {
        // Если кратко, Random использует системное время для генерации случайных чисел из-за чего
        // его легче предсказать. SecureRandom используется рандомные системные данные (интервал
        // между нажатиями клавиш итд)
        // https://www.baeldung.com/java-secure-random
        val random = SecureRandom()
        // Создаем массив байтов определенной длинны
        val salt = ByteArray(lengthByte)

        // заполняем созданыый массив случайными байтами
        random.nextBytes(salt)

        return salt
    }

}
