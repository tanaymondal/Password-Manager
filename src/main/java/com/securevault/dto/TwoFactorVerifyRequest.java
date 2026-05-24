package com.securevault.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class TwoFactorVerifyRequest {
    @NotBlank(message = "Email is required")
    private String email;

    @NotBlank(message = "Login challenge is required")
    private String challengeId;

    @NotBlank(message = "TOTP code is required")
    private String code;
}
