package com.securevault.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserInfoResponse {
    private String id;
    private String email;
    private boolean twoFactorEnabled;
    private LocalDateTime passwordUpdatedAt;
    private LocalDateTime createdAt;
}