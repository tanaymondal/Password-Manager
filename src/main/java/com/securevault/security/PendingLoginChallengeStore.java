package com.securevault.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Slf4j
@Component
public class PendingLoginChallengeStore {

    private static final long CHALLENGE_TTL_SECONDS = 300;
    private static final int MAX_ATTEMPTS_PER_CHALLENGE = 5;
    private static final String KEY_PREFIX = "challenge:";

    private final StringRedisTemplate redisTemplate;

    public PendingLoginChallengeStore(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public String createChallenge(UUID userId, String email, String deviceId) {
        String challengeId = UUID.randomUUID().toString();
        String key = KEY_PREFIX + challengeId;
        redisTemplate.opsForHash().put(key, "userId", userId.toString());
        redisTemplate.opsForHash().put(key, "email", email.toLowerCase().trim());
        redisTemplate.opsForHash().put(key, "deviceId", deviceId != null ? deviceId : "");
        redisTemplate.opsForHash().put(key, "createdAt", String.valueOf(Instant.now().toEpochMilli()));
        redisTemplate.opsForHash().put(key, "failedAttempts", "0");
        redisTemplate.expire(key, CHALLENGE_TTL_SECONDS, TimeUnit.SECONDS);
        log.debug("Created pending login challenge for user: {}", email);
        return challengeId;
    }

    public ChallengeResult validateChallenge(String challengeId, String email) {
        String key = KEY_PREFIX + challengeId;
        String storedEmail = (String) redisTemplate.opsForHash().get(key, "email");
        if (storedEmail == null) {
            throw new BadCredentialsException("Invalid or expired login challenge");
        }
        String createdAtStr = (String) redisTemplate.opsForHash().get(key, "createdAt");
        long createdAt = Long.parseLong(createdAtStr);
        if (Instant.now().isAfter(Instant.ofEpochMilli(createdAt).plusSeconds(CHALLENGE_TTL_SECONDS))) {
            log.warn("Expired login challenge used for user: {}", email);
            redisTemplate.delete(key);
            throw new BadCredentialsException("Login challenge expired. Please re-enter your password.");
        }
        if (!storedEmail.equals(email.toLowerCase().trim())) {
            log.warn("Email mismatch in login challenge. Expected: {}, got: {}", storedEmail, email);
            redisTemplate.delete(key);
            throw new BadCredentialsException("Invalid login challenge");
        }
        Long attempts = redisTemplate.opsForHash().increment(key, "failedAttempts", 1);
        if (attempts > MAX_ATTEMPTS_PER_CHALLENGE) {
            log.warn("Login challenge exhausted for user: {}", email);
            redisTemplate.delete(key);
            throw new BadCredentialsException("Too many 2FA attempts. Please re-enter your password.");
        }
        String userIdStr = (String) redisTemplate.opsForHash().get(key, "userId");
        String deviceId = (String) redisTemplate.opsForHash().get(key, "deviceId");
        return new ChallengeResult(UUID.fromString(userIdStr), deviceId);
    }

    public void consumeChallenge(String challengeId) {
        redisTemplate.delete(KEY_PREFIX + challengeId);
    }

    public record ChallengeResult(UUID userId, String deviceId) {}
}
