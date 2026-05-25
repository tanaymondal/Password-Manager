package com.securevault.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@Component
public class PendingLoginChallengeStore {

    private static final long CHALLENGE_TTL_SECONDS = 300;

    private final Map<String, Challenge> challenges = new ConcurrentHashMap<>();

    public String createChallenge(UUID userId, String email, String deviceId) {
        String challengeId = UUID.randomUUID().toString();
        challenges.put(challengeId, new Challenge(userId, email, deviceId, Instant.now()));
        log.debug("Created pending login challenge for user: {}", email);
        return challengeId;
    }

    public ChallengeResult validateChallenge(String challengeId, String email) {
        Challenge challenge = challenges.get(challengeId);
        if (challenge == null) {
            throw new BadCredentialsException("Invalid or expired login challenge");
        }
        if (Instant.now().isAfter(challenge.createdAt().plusSeconds(CHALLENGE_TTL_SECONDS))) {
            log.warn("Expired login challenge used for user: {}", email);
            challenges.remove(challengeId);
            throw new BadCredentialsException("Login challenge expired. Please re-enter your password.");
        }
        if (!challenge.email().equals(email.toLowerCase().trim())) {
            log.warn("Email mismatch in login challenge. Expected: {}, got: {}", challenge.email(), email);
            challenges.remove(challengeId);
            throw new BadCredentialsException("Invalid login challenge");
        }
        return new ChallengeResult(challenge.userId(), challenge.deviceId());
    }

    public void consumeChallenge(String challengeId) {
        challenges.remove(challengeId);
    }

    public record ChallengeResult(UUID userId, String deviceId) {}

    private record Challenge(UUID userId, String email, String deviceId, Instant createdAt) {}
}
