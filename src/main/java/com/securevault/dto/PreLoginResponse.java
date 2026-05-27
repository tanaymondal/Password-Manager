package com.securevault.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class PreLoginResponse {
    @JsonProperty("authSalt")
    private String authSalt;
}
