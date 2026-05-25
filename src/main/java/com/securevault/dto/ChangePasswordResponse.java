package com.securevault.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class ChangePasswordResponse {
    private String accessToken;

    @JsonIgnore
    private String refreshToken;

    @JsonProperty("encryptionSalt")
    private String encryptionSalt;

    private String userId;
    private String email;

    @JsonProperty("wrappedVaultKey")
    private String wrappedVaultKey;

    @JsonProperty("encryptionVersion")
    private Integer encryptionVersion;
}