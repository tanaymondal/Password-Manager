package com.securevault.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
public class SudoService {

    private static final String SUDO_PREFIX = "sudo:";
    private static final long SUDO_TTL_MINUTES = 5;

    private final StringRedisTemplate redisTemplate;

    public SudoService(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public String generateSudoToken(UUID userId) {
        String token = UUID.randomUUID().toString();
        String key = SUDO_PREFIX + userId + ":" + token;
        redisTemplate.opsForValue().set(key, "1", SUDO_TTL_MINUTES, TimeUnit.MINUTES);
        return token;
    }

    public boolean validateSudoToken(UUID userId, String token) {
        if (token == null || token.isBlank()) return false;
        String key = SUDO_PREFIX + userId + ":" + token;
        return Boolean.TRUE.equals(redisTemplate.hasKey(key));
    }

    public void consumeSudoToken(UUID userId, String token) {
        String key = SUDO_PREFIX + userId + ":" + token;
        redisTemplate.delete(key);
    }

    public void revokeAllForUser(UUID userId) {
        String pattern = SUDO_PREFIX + userId + ":*";
        redisTemplate.keys(pattern).forEach(redisTemplate::delete);
    }
}
