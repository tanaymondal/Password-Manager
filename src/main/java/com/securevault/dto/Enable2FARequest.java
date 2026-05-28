package com.securevault.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class Enable2FARequest {

    @NotBlank(message = "Verification code is required")
    @Size(min = 6, max = 6, message = "Verification code must be exactly 6 characters")
    private String code;

    @Size(min = 6, max = 6, message = "Second code must be exactly 6 characters")
    @JsonProperty("second_code")
    private String secondCode;
}