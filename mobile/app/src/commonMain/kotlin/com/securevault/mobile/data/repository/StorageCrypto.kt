package com.securevault.mobile.data.repository

expect fun encryptForStorage(plaintext: String): String

expect fun decryptForStorage(ciphertext: String): String?
