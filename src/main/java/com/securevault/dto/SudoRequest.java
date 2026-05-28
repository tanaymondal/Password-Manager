package com.securevault.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class SudoRequest {
    @NotBlank(message = "Auth hash is required")
    private String authHash;
}
