package com.securevault.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class DeleteAccountRequest {

    @NotBlank(message = "Current auth hash is required")
    @Size(max = 1024, message = "Current auth hash must not exceed 1024 characters")
    private String currentAuthHash;
}
