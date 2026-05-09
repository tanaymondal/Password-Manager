package com.securevault.repository;

import com.securevault.entity.VaultEntry;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;
import java.util.UUID;

@Repository
public interface VaultEntryRepository extends JpaRepository<VaultEntry, UUID> {

    List<VaultEntry> findByUserIdOrderByUpdatedAtDesc(UUID userId);

    void deleteByUserId(UUID userId);
}