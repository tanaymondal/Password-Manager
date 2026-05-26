package com.securevault.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class Enable2FARequest {

    @NotBlank(message = "Verification code is required")
    private String code;

    @JsonProperty("second_code")
    private String secondCode;
}