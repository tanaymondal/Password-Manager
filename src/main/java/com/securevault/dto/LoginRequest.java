package com.securevault.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class LoginRequest {

    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email format")
    private String email;

    @NotBlank(message = "Auth hash is required")
    @Size(max = 1024, message = "Auth hash must not exceed 1024 characters")
    private String authHash;

    private String deviceName;
    private String deviceId;
}