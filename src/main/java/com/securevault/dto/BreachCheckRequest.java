package com.securevault.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class BreachCheckRequest {

    @NotBlank(message = "SHA-1 hash is required")
    @Size(min = 40, max = 40, message = "Invalid SHA-1 hash")
    private String sha1Hash;
}
