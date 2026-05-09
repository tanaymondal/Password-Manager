package com.securevault.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import java.util.List;

@Data
@AllArgsConstructor
public class VaultEntriesResponse {
    private List<VaultEntryResponse> entries;
    private int count;
}