package com.securevault.mobile.data.api

import com.securevault.mobile.data.model.*
import com.securevault.mobile.data.repository.SessionManager
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.plugins.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class SecureVaultApi(
    private val baseUrl: String,
    private val httpClient: HttpClient
) {
    private val refreshMutex = Mutex()

    class TokenExpiredException : Exception("Token expired or invalid")
    class SessionExpiredException : Exception("Session expired. Please login again.")

    private suspend fun authRequest(block: suspend () -> HttpResponse): HttpResponse {
        val response = block()
        if (response.status == HttpStatusCode.Unauthorized || response.status == HttpStatusCode.Forbidden) {
            throw TokenExpiredException()
        }
        return response
    }

    suspend fun prelogin(request: PreLoginRequest): Result<PreLoginResponse> {
        return try {
            val response: HttpResponse = httpClient.post("$baseUrl/api/v1/auth/prelogin") {
                contentType(ContentType.Application.Json)
                setBody(request)
            }
            val body = response.bodyAsText()
            val apiResponse = Json.decodeFromString<ApiResponse<PreLoginResponse>>(body)
            apiResponse.data?.let { Result.success(it) }
                ?: Result.failure(Exception(apiResponse.message ?: "Prelogin failed"))
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun register(request: RegisterRequest): Result<AuthResponse> {
        return try {
            val response: HttpResponse = httpClient.post("$baseUrl/api/v1/auth/register") {
                contentType(ContentType.Application.Json)
                setBody(request)
            }
            parseAuthResponse(response)
        } catch (e: TokenExpiredException) {
            Result.failure(Exception("Invalid email or password"))
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun login(request: LoginRequest): Result<AuthResponse> {
        return try {
            val response: HttpResponse = httpClient.post("$baseUrl/api/v1/auth/login") {
                contentType(ContentType.Application.Json)
                setBody(request)
            }
            parseAuthResponse(response)
        } catch (e: TokenExpiredException) {
            Result.failure(Exception("Invalid email or password"))
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun verifyTwoFactor(email: String, challengeId: String, code: String): Result<AuthResponse> {
        return try {
            val response: HttpResponse = httpClient.post("$baseUrl/api/v1/auth/verify-2fa") {
                contentType(ContentType.Application.Json)
                setBody(TwoFactorVerifyRequest(email, challengeId, code))
            }
            parseAuthResponse(response)
        } catch (e: TokenExpiredException) {
            Result.failure(Exception("Invalid email or password"))
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun refreshToken(request: RefreshTokenRequest): Result<AuthResponse> = runCatching {
        val response: HttpResponse = httpClient.post("$baseUrl/api/v1/auth/refresh") {
            contentType(ContentType.Application.Json)
            setBody(request)
        }
        val body = response.bodyAsText()
        val apiResponse: AuthApiResponse = Json.decodeFromString(body)
        apiResponse.data ?: throw Exception(apiResponse.message ?: "Token refresh failed")
    }

    suspend fun logout(): Result<Unit> = runCatching {
        httpClient.post("$baseUrl/api/v1/auth/logout") {
            val token = getAccessToken()
            if (token.isNotEmpty()) bearerAuth(token)
            contentType(ContentType.Application.Json)
            setBody(RefreshTokenRequest(SessionManager.getRefreshToken()))
        }
    }

    suspend fun getVaultEntries(): Result<List<VaultEntryResponse>> =
        authCall { token ->
            val response: HttpResponse = authRequest {
                httpClient.get("$baseUrl/api/v1/vault") { bearerAuth(token) }
            }
            val body = response.bodyAsText()
            val apiResponse: VaultEntriesApiResponse = Json.decodeFromString(body)
            apiResponse.data?.entries ?: throw Exception(apiResponse.message ?: "Failed to get entries")
        }

    suspend fun getVaultEntry(id: String): Result<VaultEntryResponse> =
        authCall { token ->
            val response: HttpResponse = authRequest {
                httpClient.get("$baseUrl/api/v1/vault/$id") { bearerAuth(token) }
            }
            val body = response.bodyAsText()
            val apiResponse: VaultEntryApiResponse = Json.decodeFromString(body)
            apiResponse.data ?: throw Exception(apiResponse.message ?: "Failed to get entry")
        }

    suspend fun createVaultEntry(request: VaultEntryRequest): Result<VaultEntryResponse> =
        authCall { token ->
            val response: HttpResponse = authRequest {
                httpClient.post("$baseUrl/api/v1/vault") {
                    bearerAuth(token)
                    contentType(ContentType.Application.Json)
                    setBody(request)
                }
            }
            val body = response.bodyAsText()
            val apiResponse: VaultEntryApiResponse = Json.decodeFromString(body)
            apiResponse.data ?: throw Exception(apiResponse.message ?: "Failed to create entry")
        }

    suspend fun updateVaultEntry(id: String, request: VaultEntryRequest): Result<VaultEntryResponse> =
        authCall { token ->
            val response: HttpResponse = authRequest {
                httpClient.put("$baseUrl/api/v1/vault/$id") {
                    bearerAuth(token)
                    contentType(ContentType.Application.Json)
                    setBody(request)
                }
            }
            val body = response.bodyAsText()
            val apiResponse: VaultEntryApiResponse = Json.decodeFromString(body)
            apiResponse.data ?: throw Exception(apiResponse.message ?: "Failed to update entry")
        }

    suspend fun deleteVaultEntry(id: String): Result<Unit> =
        authCallVoid { token ->
            authRequest {
                httpClient.delete("$baseUrl/api/v1/vault/$id") { bearerAuth(token) }
            }
        }

    suspend fun deleteAllVaultEntries(): Result<Unit> =
        authCallVoid { token ->
            authRequest {
                httpClient.delete("$baseUrl/api/v1/vault") { bearerAuth(token) }
            }
        }

    suspend fun getDevices(): Result<List<DeviceResponse>> =
        authCall { token ->
            val response: HttpResponse = authRequest {
                httpClient.get("$baseUrl/api/v1/devices") { bearerAuth(token) }
            }
            val body = response.bodyAsText()
            val apiResponse: DevicesApiResponse = Json.decodeFromString(body)
            apiResponse.data?.devices ?: throw Exception(apiResponse.message ?: "Failed to get devices")
        }

    suspend fun registerDevice(request: DeviceRequest): Result<DeviceResponse> =
        authCall { token ->
            val response: HttpResponse = authRequest {
                httpClient.post("$baseUrl/api/v1/devices") {
                    bearerAuth(token)
                    contentType(ContentType.Application.Json)
                    setBody(request)
                }
            }
            val body = response.bodyAsText()
            val apiResponse: DeviceApiResponse = Json.decodeFromString(body)
            apiResponse.data ?: throw Exception(apiResponse.message ?: "Failed to register device")
        }

    suspend fun removeDevice(id: Long): Result<Unit> =
        authCallVoid { token ->
            authRequest {
                httpClient.delete("$baseUrl/api/v1/devices/$id") { bearerAuth(token) }
            }
        }

    suspend fun setupTwoFactor(): Result<TwoFactorSetupResponse> =
        authCall { token ->
            val response: HttpResponse = authRequest {
                httpClient.get("$baseUrl/api/v1/2fa/setup") { bearerAuth(token) }
            }
            val body = response.bodyAsText()
            val apiResponse: ApiResponse<TwoFactorSetupResponse> = Json.decodeFromString(body)
            apiResponse.data ?: throw Exception(apiResponse.message ?: "Failed to setup 2FA")
        }

    suspend fun enableTwoFactor(request: EnableTwoFactorRequest): Result<Unit> =
        authCallVoid { token ->
            authRequest {
                httpClient.post("$baseUrl/api/v1/2fa/enable") {
                    bearerAuth(token)
                    contentType(ContentType.Application.Json)
                    setBody(request)
                }
            }
        }

    suspend fun disableTwoFactor(code: String): Result<Unit> =
        authCallVoid { token ->
            authRequest {
                httpClient.post("$baseUrl/api/v1/2fa/disable") {
                    bearerAuth(token)
                    contentType(ContentType.Application.Json)
                    setBody(mapOf("code" to code))
                }
            }
        }

    suspend fun getTwoFactorStatus(): Result<TwoFactorStatusResponse> =
        authCall { token ->
            val response: HttpResponse = authRequest {
                httpClient.get("$baseUrl/api/v1/2fa/status") { bearerAuth(token) }
            }
            val body = response.bodyAsText()
            val apiResponse: ApiResponse<TwoFactorStatusResponse> = Json.decodeFromString(body)
            apiResponse.data ?: throw Exception(apiResponse.message ?: "Failed to get 2FA status")
        }

    suspend fun getHealth(): Result<HealthResponse> = runCatching {
        val response: HttpResponse = httpClient.get("$baseUrl/api/v1/health")
        val body = response.bodyAsText()
        Json.decodeFromString(body)
    }

    private suspend fun <T> authCall(block: suspend (accessToken: String) -> T): Result<T> = runCatching {
        val token = getAccessToken()
        if (token.isEmpty()) throw Exception("Not authenticated")

        try {
            block(token)
        } catch (e: Exception) {
            if (isUnauthorized(e) && refreshAccessToken()) {
                block(getAccessToken())
            } else if (isUnauthorized(e)) {
                throw SessionExpiredException()
            } else {
                throw e
            }
        }
    }

    private suspend fun authCallVoid(block: suspend (accessToken: String) -> Unit): Result<Unit> = runCatching {
        val token = getAccessToken()
        if (token.isEmpty()) throw Exception("Not authenticated")

        try {
            block(token)
        } catch (e: Exception) {
            if (isUnauthorized(e) && refreshAccessToken()) {
                block(getAccessToken())
            } else if (isUnauthorized(e)) {
                throw SessionExpiredException()
            } else {
                throw e
            }
        }
    }

    private fun getAccessToken(): String {
        return SessionManager.getAccessToken()
    }

    private suspend fun refreshAccessToken(): Boolean = refreshMutex.withLock {
        val currentRefreshToken = SessionManager.getRefreshToken()
        if (currentRefreshToken.isEmpty()) {
            SessionManager.clearSession()
            return false
        }

        try {
            val response = httpClient.post("$baseUrl/api/v1/auth/refresh") {
                contentType(ContentType.Application.Json)
                setBody(RefreshTokenRequest(currentRefreshToken))
            }
            val body = response.bodyAsText()
            val apiResponse: AuthApiResponse = Json.decodeFromString(body)
            val authData = apiResponse.data ?: return false

            SessionManager.setAccessToken(authData.accessToken ?: return false)
            SessionManager.setRefreshToken(authData.refreshToken ?: currentRefreshToken)
            authData.encryptionSalt?.let { SessionManager.setEncryptionSalt(it) }
            authData.wrappedVaultKey?.let { SessionManager.setWrappedVaultKey(it) }
            authData.userId?.let { SessionManager.setUserId(it) }
            authData.email?.let { SessionManager.setUserEmail(it) }
            authData.encryptionVersion?.let { SessionManager.setEncryptionVersion(it) }
            true
        } catch (e: Exception) {
            SessionManager.clearSession()
            false
        }
    }

    private fun isUnauthorized(e: Exception): Boolean {
        if (e is SessionExpiredException) return false
        if (e is TokenExpiredException) return true
        val message = e.message ?: ""
        return message.contains("401") || message.contains("403") ||
                message.contains("Unauthorized") || message.contains("unauthorized") ||
                message.contains("Forbidden") || message.contains("forbidden") ||
                message.contains("expired")
    }

    private suspend fun parseAuthResponse(response: HttpResponse): Result<AuthResponse> = runCatching {
        val body = response.bodyAsText()

        val json = Json.parseToJsonElement(body)
        val success = json.jsonObject["success"]?.jsonPrimitive?.content?.toBoolean() ?: false
        val message = json.jsonObject["message"]?.jsonPrimitive?.content
        val dataObj = json.jsonObject["data"]?.jsonObject

        if (!success) {
            val errorMessage = if (dataObj != null) {
                dataObj.entries.joinToString(", ") { "${it.key}: ${it.value.jsonPrimitive.content}" }
            } else message
            throw Exception(errorMessage ?: "Request failed")
        }

        val accessToken = dataObj?.get("accessToken")?.jsonPrimitive?.content
        val refreshToken = dataObj?.get("refreshToken")?.jsonPrimitive?.content
        val encryptionSalt = dataObj?.get("encryptionSalt")?.jsonPrimitive?.content
        val userId = dataObj?.get("userId")?.jsonPrimitive?.content
        val email = dataObj?.get("email")?.jsonPrimitive?.content
        val wrappedVaultKey = dataObj?.get("wrappedVaultKey")?.jsonPrimitive?.content
        val encryptionVersion = dataObj?.get("encryptionVersion")?.jsonPrimitive?.content?.toIntOrNull() ?: 2
        val twoFactorRequired = dataObj?.get("twoFactorRequired")?.jsonPrimitive?.content?.toBoolean() ?: false
        val challengeId = dataObj?.get("challengeId")?.jsonPrimitive?.content

        if (twoFactorRequired) {
            if (userId == null || email == null || encryptionSalt == null || challengeId == null) {
                throw Exception("Missing required fields for 2FA verification")
            }
            AuthResponse(
                userId = userId,
                email = email,
                challengeId = challengeId,
                encryptionSalt = encryptionSalt,
                wrappedVaultKey = wrappedVaultKey,
                encryptionVersion = encryptionVersion,
                twoFactorRequired = true
            )
        } else {
            AuthResponse(
            accessToken = accessToken ?: throw Exception("Missing accessToken"),
            refreshToken = refreshToken ?: throw Exception("Missing refreshToken"),
            encryptionSalt = encryptionSalt ?: throw Exception("Missing encryptionSalt"),
            userId = userId ?: throw Exception("Missing userId"),
            email = email ?: throw Exception("Missing email"),
            wrappedVaultKey = wrappedVaultKey,
            encryptionVersion = encryptionVersion,
            twoFactorRequired = false
            )
        }
    }

    companion object {
        fun create(baseUrl: String): SecureVaultApi {
            val client = HttpClient {
                install(ContentNegotiation) {
                    json(Json {
                        prettyPrint = true
                        isLenient = true
                        ignoreUnknownKeys = true
                    })
                }
                install(HttpTimeout) {
                    requestTimeoutMillis = 30000
                    connectTimeoutMillis = 15000
                }
                defaultRequest {
                    contentType(ContentType.Application.Json)
                }
            }
            return SecureVaultApi(baseUrl, client)
        }
    }
}
