package com.securevault.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class TwoFactorLoginResponse {
    private boolean twoFactorRequired;
    private String userId;
    private String email;
    private String challengeId;

    @JsonProperty("authSalt")
    private String authSalt;

    @JsonProperty("twoFactorMethods")
    private List<String> twoFactorMethods;

    @JsonProperty("kdfIterations")
    private Integer kdfIterations;

    @JsonProperty("kdfMemory")
    private Integer kdfMemory;

    @JsonProperty("kdfParallelism")
    private Integer kdfParallelism;

    public static TwoFactorLoginResponse requireTwoFactor(String userId, String email, String challengeId, String authSalt, List<String> twoFactorMethods, Integer kdfIterations, Integer kdfMemory, Integer kdfParallelism) {
        return new TwoFactorLoginResponse(true, userId, email, challengeId, authSalt, twoFactorMethods, kdfIterations, kdfMemory, kdfParallelism);
    }
}
