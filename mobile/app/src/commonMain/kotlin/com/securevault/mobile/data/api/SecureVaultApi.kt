package com.securevault.mobile.data.api

import com.securevault.mobile.data.model.*
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.plugins.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import android.util.Log

class SecureVaultApi(
    private val baseUrl: String,
    private val httpClient: HttpClient
) {
    private val tag = "SecureVaultApi"

    suspend fun register(request: RegisterRequest): Result<AuthResponse> {
        return try {
            Log.d(tag, "POST /api/v1/auth/register - Request: $request")
            val response: HttpResponse = httpClient.post("$baseUrl/api/v1/auth/register") {
                contentType(ContentType.Application.Json)
                setBody(request)
            }
            val body = response.bodyAsText()
            Log.d(tag, "Response body: $body")
            
            val json = Json.parseToJsonElement(body)
            val success = json.jsonObject["success"]?.jsonPrimitive?.content?.toBoolean() ?: false
            val message = json.jsonObject["message"]?.jsonPrimitive?.content
            val dataObj = json.jsonObject["data"]?.jsonObject
            
            if (!success) {
                val errorMessage = if (dataObj != null) {
                    dataObj.entries.joinToString(", ") { "${it.key}: ${it.value.jsonPrimitive.content}" }
                } else message
                Log.e(tag, "Registration failed: $errorMessage")
                throw Exception(errorMessage ?: "Registration failed")
            }
            
            val accessToken = dataObj?.get("accessToken")?.jsonPrimitive?.content 
                ?: throw Exception("Missing accessToken")
            val refreshToken = dataObj?.get("refreshToken")?.jsonPrimitive?.content 
                ?: throw Exception("Missing refreshToken")
            val encryptionSalt = dataObj?.get("encryptionSalt")?.jsonPrimitive?.content 
                ?: throw Exception("Missing encryptionSalt")
            val userId = dataObj?.get("userId")?.jsonPrimitive?.content 
                ?: throw Exception("Missing userId")
            val email = dataObj?.get("email")?.jsonPrimitive?.content 
                ?: throw Exception("Missing email")
            val wrappedVaultKey = dataObj?.get("wrappedVaultKey")?.jsonPrimitive?.content
            val encryptionVersion = dataObj?.get("encryptionVersion")?.jsonPrimitive?.content?.toIntOrNull() ?: 1
            
            Log.d(tag, "Parsed AuthResponse successfully")
            Result.success(AuthResponse(accessToken, refreshToken, encryptionSalt, userId, email, wrappedVaultKey, encryptionVersion))
        } catch (e: Exception) {
            Log.e(tag, "Registration error: ${e.message}")
            Result.failure(e)
        }
    }

    suspend fun login(request: LoginRequest): Result<AuthResponse> {
        return try {
            Log.d(tag, "POST /api/v1/auth/login - Request: $request")
            val response: HttpResponse = httpClient.post("$baseUrl/api/v1/auth/login") {
                contentType(ContentType.Application.Json)
                setBody(request)
            }
            val body = response.bodyAsText()
            Log.d(tag, "Response body: $body")
            
            val json = Json.parseToJsonElement(body)
            val success = json.jsonObject["success"]?.jsonPrimitive?.content?.toBoolean() ?: false
            val message = json.jsonObject["message"]?.jsonPrimitive?.content
            val dataObj = json.jsonObject["data"]?.jsonObject
            
            if (!success) {
                val errorMessage = if (dataObj != null) {
                    dataObj.entries.joinToString(", ") { "${it.key}: ${it.value.jsonPrimitive.content}" }
                } else message
                Log.e(tag, "Login failed: $errorMessage")
                throw Exception(errorMessage ?: "Login failed")
            }
            
            val accessToken = dataObj?.get("accessToken")?.jsonPrimitive?.content 
                ?: throw Exception("Missing accessToken")
            val refreshToken = dataObj?.get("refreshToken")?.jsonPrimitive?.content 
                ?: throw Exception("Missing refreshToken")
            val encryptionSalt = dataObj?.get("encryptionSalt")?.jsonPrimitive?.content 
                ?: throw Exception("Missing encryptionSalt")
            val userId = dataObj?.get("userId")?.jsonPrimitive?.content 
                ?: throw Exception("Missing userId")
            val email = dataObj?.get("email")?.jsonPrimitive?.content 
                ?: throw Exception("Missing email")
            val wrappedVaultKey = dataObj?.get("wrappedVaultKey")?.jsonPrimitive?.content
            val encryptionVersion = dataObj?.get("encryptionVersion")?.jsonPrimitive?.content?.toIntOrNull() ?: 1
            
            Log.d(tag, "Parsed AuthResponse successfully")
            Result.success(AuthResponse(accessToken, refreshToken, encryptionSalt, userId, email, wrappedVaultKey, encryptionVersion))
        } catch (e: Exception) {
            Log.e(tag, "Login error: ${e.message}")
            Result.failure(e)
        }
    }

    suspend fun refreshToken(request: RefreshTokenRequest): Result<AuthResponse> = runCatching {
        Log.d(tag, "POST /api/v1/auth/refresh")
        val response: HttpResponse = httpClient.post("$baseUrl/api/v1/auth/refresh") {
            contentType(ContentType.Application.Json)
            setBody(request)
        }
        val body = response.bodyAsText()
        Log.d(tag, "Response body: $body")
        val apiResponse: AuthApiResponse = Json.decodeFromString(body)
        apiResponse.data ?: throw Exception(apiResponse.message ?: "Token refresh failed")
    }

    suspend fun logout(accessToken: String): Result<Unit> = runCatching {
        Log.d(tag, "POST /api/v1/auth/logout")
        httpClient.post("$baseUrl/api/v1/auth/logout") {
            bearerAuth(accessToken)
        }
    }

    suspend fun changePassword(accessToken: String, request: ChangePasswordRequest): Result<ChangePasswordResponse> = runCatching {
        Log.d(tag, "POST /api/v1/auth/change-password - newSalt=${request.newEncryptionSalt}")
        val response: HttpResponse = httpClient.post("$baseUrl/api/v1/auth/change-password") {
            bearerAuth(accessToken)
            contentType(ContentType.Application.Json)
            setBody(request)
        }
        val body = response.bodyAsText()
        Log.d(tag, "Response body: $body")
        val apiResponse: ApiResponse<ChangePasswordResponse> = Json.decodeFromString(body)
        apiResponse.data ?: throw Exception(apiResponse.message ?: "Password change failed")
    }

    suspend fun getVaultEntries(accessToken: String): Result<List<VaultEntryResponse>> = runCatching {
        Log.d(tag, "GET /api/v1/vault")
        val response: HttpResponse = httpClient.get("$baseUrl/api/v1/vault") {
            bearerAuth(accessToken)
        }
        val body = response.bodyAsText()
        Log.d(tag, "Response body: $body")
        val apiResponse: VaultEntriesApiResponse = Json.decodeFromString(body)
        apiResponse.data?.entries ?: throw Exception(apiResponse.message ?: "Failed to get entries")
    }

    suspend fun getVaultEntry(accessToken: String, id: String): Result<VaultEntryResponse> = runCatching {
        Log.d(tag, "GET /api/v1/vault/$id")
        val response: HttpResponse = httpClient.get("$baseUrl/api/v1/vault/$id") {
            bearerAuth(accessToken)
        }
        val body = response.bodyAsText()
        Log.d(tag, "Response body: $body")
        val apiResponse: VaultEntryApiResponse = Json.decodeFromString(body)
        apiResponse.data ?: throw Exception(apiResponse.message ?: "Failed to get entry")
    }

    suspend fun createVaultEntry(accessToken: String, request: VaultEntryRequest): Result<VaultEntryResponse> = runCatching {
        Log.d(tag, "POST /api/v1/vault - Request: $request")
        val response: HttpResponse = httpClient.post("$baseUrl/api/v1/vault") {
            bearerAuth(accessToken)
            contentType(ContentType.Application.Json)
            setBody(request)
        }
        val body = response.bodyAsText()
        Log.d(tag, "Response body: $body")
        val apiResponse: VaultEntryApiResponse = Json.decodeFromString(body)
        apiResponse.data ?: throw Exception(apiResponse.message ?: "Failed to create entry")
    }

    suspend fun updateVaultEntry(accessToken: String, id: String, request: VaultEntryRequest): Result<VaultEntryResponse> = runCatching {
        Log.d(tag, "PUT /api/v1/vault/$id - Request: $request")
        val response: HttpResponse = httpClient.put("$baseUrl/api/v1/vault/$id") {
            bearerAuth(accessToken)
            contentType(ContentType.Application.Json)
            setBody(request)
        }
        val body = response.bodyAsText()
        Log.d(tag, "Response body: $body")
        val apiResponse: VaultEntryApiResponse = Json.decodeFromString(body)
        apiResponse.data ?: throw Exception(apiResponse.message ?: "Failed to update entry")
    }

    suspend fun deleteVaultEntry(accessToken: String, id: String): Result<Unit> = runCatching {
        Log.d(tag, "DELETE /api/v1/vault/$id")
        httpClient.delete("$baseUrl/api/v1/vault/$id") {
            bearerAuth(accessToken)
        }
    }

    suspend fun deleteAllVaultEntries(accessToken: String): Result<Unit> = runCatching {
        Log.d(tag, "DELETE /api/v1/vault")
        httpClient.delete("$baseUrl/api/v1/vault") {
            bearerAuth(accessToken)
        }
    }

    suspend fun getDevices(accessToken: String): Result<List<DeviceResponse>> = runCatching {
        Log.d(tag, "GET /api/v1/devices")
        val response: HttpResponse = httpClient.get("$baseUrl/api/v1/devices") {
            bearerAuth(accessToken)
        }
        val body = response.bodyAsText()
        Log.d(tag, "Response body: $body")
        val apiResponse: DevicesApiResponse = Json.decodeFromString(body)
        apiResponse.data?.devices ?: throw Exception(apiResponse.message ?: "Failed to get devices")
    }

    suspend fun registerDevice(accessToken: String, request: DeviceRequest): Result<DeviceResponse> = runCatching {
        Log.d(tag, "POST /api/v1/devices")
        val response: HttpResponse = httpClient.post("$baseUrl/api/v1/devices") {
            bearerAuth(accessToken)
            contentType(ContentType.Application.Json)
            setBody(request)
        }
        val body = response.bodyAsText()
        Log.d(tag, "Response body: $body")
        val apiResponse: DeviceApiResponse = Json.decodeFromString(body)
        apiResponse.data ?: throw Exception(apiResponse.message ?: "Failed to register device")
    }

    suspend fun removeDevice(accessToken: String, id: Long): Result<Unit> = runCatching {
        Log.d(tag, "DELETE /api/v1/devices/$id")
        httpClient.delete("$baseUrl/api/v1/devices/$id") {
            bearerAuth(accessToken)
        }
    }

    suspend fun setupTwoFactor(accessToken: String): Result<TwoFactorSetupResponse> = runCatching {
        Log.d(tag, "GET /api/v1/2fa/setup")
        val response: HttpResponse = httpClient.get("$baseUrl/api/v1/2fa/setup") {
            bearerAuth(accessToken)
        }
        val body = response.bodyAsText()
        Log.d(tag, "Response body: $body")
        val apiResponse: ApiResponse<TwoFactorSetupResponse> = Json.decodeFromString(body)
        apiResponse.data ?: throw Exception(apiResponse.message ?: "Failed to setup 2FA")
    }

    suspend fun enableTwoFactor(accessToken: String, request: EnableTwoFactorRequest): Result<Unit> = runCatching {
        Log.d(tag, "POST /api/v1/2fa/enable")
        httpClient.post("$baseUrl/api/v1/2fa/enable") {
            bearerAuth(accessToken)
            contentType(ContentType.Application.Json)
            setBody(request)
        }
    }

    suspend fun disableTwoFactor(accessToken: String, code: String): Result<Unit> = runCatching {
        Log.d(tag, "POST /api/v1/2fa/disable")
        httpClient.post("$baseUrl/api/v1/2fa/disable") {
            bearerAuth(accessToken)
            contentType(ContentType.Application.Json)
            setBody(mapOf("code" to code))
        }
    }

    suspend fun getTwoFactorStatus(accessToken: String): Result<TwoFactorStatusResponse> = runCatching {
        Log.d(tag, "GET /api/v1/2fa/status")
        val response: HttpResponse = httpClient.get("$baseUrl/api/v1/2fa/status") {
            bearerAuth(accessToken)
        }
        val body = response.bodyAsText()
        Log.d(tag, "Response body: $body")
        val apiResponse: ApiResponse<TwoFactorStatusResponse> = Json.decodeFromString(body)
        apiResponse.data ?: throw Exception(apiResponse.message ?: "Failed to get 2FA status")
    }

    suspend fun getHealth(): Result<HealthResponse> = runCatching {
        Log.d(tag, "GET /api/v1/health")
        val response: HttpResponse = httpClient.get("$baseUrl/api/v1/health")
        val body = response.bodyAsText()
        Log.d(tag, "Response body: $body")
        Json.decodeFromString(body)
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