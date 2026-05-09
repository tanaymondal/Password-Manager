package com.securevault.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class VaultEntryResponse {
    private String id;
    private String encryptedData;
    private String iv;
    private Integer version;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
}