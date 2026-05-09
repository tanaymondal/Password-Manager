package com.securevault.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class Enable2FARequest {

    @NotBlank(message = "Verification code is required")
    private String code;
}