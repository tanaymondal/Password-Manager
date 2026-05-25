package com.securevault.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
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
    private String challengeId;

    @JsonProperty("authSalt")
    private String authSalt;

    @JsonProperty("encryptionSalt")
    private String encryptionSalt;

    @JsonProperty("wrappedVaultKey")
    private String wrappedVaultKey;

    @JsonProperty("encryptionVersion")
    private Integer encryptionVersion;

    private String accessToken;

    @JsonIgnore
    private String refreshToken;

    public static TwoFactorLoginResponse requireTwoFactor(String userId, String email, String challengeId, String authSalt, String encryptionSalt, String wrappedVaultKey, Integer encryptionVersion) {
        return new TwoFactorLoginResponse(true, userId, email, challengeId, authSalt, encryptionSalt, wrappedVaultKey, encryptionVersion, null, null);
    }

    public static TwoFactorLoginResponse loginSuccess(String accessToken, String refreshToken, String userId, String email, String authSalt, String encryptionSalt, String wrappedVaultKey, Integer encryptionVersion) {
        return new TwoFactorLoginResponse(false, userId, email, null, authSalt, encryptionSalt, wrappedVaultKey, encryptionVersion, accessToken, refreshToken);
    }
}
