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

/**
 * Service for managing vault entries (password records).
 *
 * This service implements ZERO-KNOWLEDGE storage - it never accesses, reads, or
 * processes the actual vault data in plaintext. All data is stored as encrypted
 * blobs that only the client can decrypt.
 *
 * ARCHITECTURE:
 * - Client encrypts vault entries using AES-256-GCM with a vault key
 * - Encrypted data (encryptedData) and IV (iv) are sent to the server
 * - Server stores these as opaque blobs - it cannot decrypt them
 * - Server only handles CRUD operations on these blobs
 * - Client is responsible for all encryption/decryption
 *
 * SECURITY:
 * - User authorization is verified for every operation
 * - Users can only access their own vault entries
 * - No plaintext data ever touches the server
 *
 * @see VaultEntry for entity definition
 * @see VaultEntryRepository for database operations
 */
@Service
@RequiredArgsConstructor
public class VaultService {

    private final VaultEntryRepository vaultEntryRepository;

    /**
     * Creates a new vault entry for a user.
     *
     * The entry contains encrypted data that the server cannot decrypt.
     * Only the IV (initialization vector) and ciphertext are stored.
     *
     * @param userId UUID of the user creating the entry
     * @param request Contains encryptedData and iv from client-side encryption
     * @return VaultEntryResponse with the created entry's metadata and ID
     * @throws IllegalArgumentException if data is invalid
     */
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

    /**
     * Retrieves all vault entries for a user.
     *
     * Returns a list of encrypted blobs. The client must decrypt each entry
     * using the vault key to access the actual data (title, username, password, etc.)
     *
     * @param userId UUID of the user
     * @return VaultEntriesResponse containing list of encrypted entries and count
     */
    @Transactional(readOnly = true)
    public VaultEntriesResponse getAllEntries(UUID userId) {
        List<VaultEntry> entries = vaultEntryRepository.findByUserIdOrderByCreatedAtAsc(userId);
        List<VaultEntryResponse> responses = entries.stream()
                .map(this::toResponse)
                .collect(Collectors.toList());

        return new VaultEntriesResponse(responses, responses.size());
    }

    /**
     * Retrieves a single vault entry by ID.
     *
     * Verifies that the entry belongs to the requesting user before returning.
     * Returns encrypted data that the client must decrypt.
     *
     * @param userId UUID of the user requesting the entry
     * @param entryId UUID string of the vault entry
     * @return VaultEntryResponse with encrypted entry data
     * @throws IllegalArgumentException if entry not found or access denied
     */
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

    /**
     * Updates an existing vault entry.
     *
     * The client sends new encrypted data (likely with a new IV) that replaces
     * the existing entry. This is typically used when the user updates password
     * or other details, requiring re-encryption with the vault key.
     *
     * @param userId UUID of the user updating the entry
     * @param entryId UUID string of the vault entry to update
     * @param request Contains new encryptedData and iv
     * @return VaultEntryResponse with updated entry metadata
     * @throws IllegalArgumentException if entry not found or access denied
     */
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

    /**
     * Deletes a single vault entry.
     *
     * Permanently removes the entry from storage. The operation is irreversible.
     *
     * @param userId UUID of the user deleting the entry
     * @param entryId UUID string of the vault entry to delete
     * @throws IllegalArgumentException if entry not found or access denied
     */
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

    /**
     * Deletes all vault entries for a user.
     *
     * Used during account deletion or vault reset. Permanently removes all
     * encrypted entries associated with the user.
     *
     * @param userId UUID of the user whose entries should be deleted
     */
    @Transactional
    public void deleteAllEntries(UUID userId) {
        vaultEntryRepository.deleteByUserId(userId);
    }

    /**
     * Converts a VaultEntry entity to a VaultEntryResponse DTO.
     *
     * @param entry Database entity
     * @return Response DTO with entry data
     */
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