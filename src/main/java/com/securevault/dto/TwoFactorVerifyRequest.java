package com.securevault.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class TwoFactorVerifyRequest {
    @NotBlank(message = "Email is required")
    private String email;

    @NotBlank(message = "TOTP code is required")
    private String code;
}
