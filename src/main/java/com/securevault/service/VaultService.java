package com.securevault.service;

import com.securevault.dto.VaultEntriesResponse;
import com.securevault.dto.VaultEntryRequest;
import com.securevault.dto.VaultEntryResponse;
import com.securevault.entity.VaultEntry;
import com.securevault.repository.VaultEntryRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class VaultService {

    private final VaultEntryRepository vaultEntryRepository;

    @Transactional
    public VaultEntryResponse createEntry(UUID userId, VaultEntryRequest request) {
        VaultEntry entry = new VaultEntry();
        entry.setUserId(userId);
        entry.setEncryptedData(request.getEncryptedData());
        entry.setIv(request.getIv());
        entry.setVersion(1);

        entry = vaultEntryRepository.save(entry);

        return toResponse(entry);
    }

    @Transactional(readOnly = true)
    public VaultEntriesResponse getAllEntries(UUID userId) {
        List<VaultEntry> entries = vaultEntryRepository.findByUserIdOrderByCreatedAtAsc(userId);
        List<VaultEntryResponse> responses = entries.stream()
                .map(this::toResponse)
                .collect(Collectors.toList());

        return new VaultEntriesResponse(responses, responses.size());
    }

    @Transactional(readOnly = true)
    public VaultEntryResponse getEntry(UUID userId, String entryId) {
        UUID uuid = UUID.fromString(entryId);
        VaultEntry entry = vaultEntryRepository.findById(uuid)
                .orElseThrow(() -> new IllegalArgumentException("Entry not found"));

        if (!entry.getUserId().equals(userId)) {
            throw new IllegalArgumentException("Access denied");
        }

        return toResponse(entry);
    }

    @Transactional
    public VaultEntryResponse updateEntry(UUID userId, String entryId, VaultEntryRequest request) {
        UUID uuid = UUID.fromString(entryId);
        VaultEntry entry = vaultEntryRepository.findById(uuid)
                .orElseThrow(() -> new IllegalArgumentException("Entry not found"));

        if (!entry.getUserId().equals(userId)) {
            throw new IllegalArgumentException("Access denied");
        }

        entry.setEncryptedData(request.getEncryptedData());
        entry.setIv(request.getIv());

        entry = vaultEntryRepository.save(entry);

        return toResponse(entry);
    }

    @Transactional
    public void deleteEntry(UUID userId, String entryId) {
        UUID uuid = UUID.fromString(entryId);
        VaultEntry entry = vaultEntryRepository.findById(uuid)
                .orElseThrow(() -> new IllegalArgumentException("Entry not found"));

        if (!entry.getUserId().equals(userId)) {
            throw new IllegalArgumentException("Access denied");
        }

        vaultEntryRepository.delete(entry);
    }

    @Transactional
    public void deleteAllEntries(UUID userId) {
        vaultEntryRepository.deleteByUserId(userId);
    }

    private VaultEntryResponse toResponse(VaultEntry entry) {
        return new VaultEntryResponse(
                entry.getId().toString(),
                entry.getEncryptedData(),
                entry.getIv(),
                entry.getVersion(),
                entry.getCreatedAt(),
                entry.getUpdatedAt()
        );
    }
}