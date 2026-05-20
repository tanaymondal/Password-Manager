package com.securevault.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class TwoFactorLoginResponse {
    private boolean twoFactorRequired;
    private String userId;
    private String email;

    @JsonProperty("encryptionSalt")
    private String encryptionSalt;

    @JsonProperty("wrappedVaultKey")
    private String wrappedVaultKey;

    @JsonProperty("encryptionVersion")
    private Integer encryptionVersion;

    private String accessToken;
    private String refreshToken;

    public static TwoFactorLoginResponse requireTwoFactor(String userId, String email, String encryptionSalt, String wrappedVaultKey, Integer encryptionVersion) {
        return new TwoFactorLoginResponse(true, userId, email, encryptionSalt, wrappedVaultKey, encryptionVersion, null, null);
    }

    public static TwoFactorLoginResponse loginSuccess(String accessToken, String refreshToken, String userId, String email, String encryptionSalt, String wrappedVaultKey, Integer encryptionVersion) {
        return new TwoFactorLoginResponse(false, userId, email, encryptionSalt, wrappedVaultKey, encryptionVersion, accessToken, refreshToken);
    }
}
