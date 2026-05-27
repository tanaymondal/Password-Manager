package com.securevault.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.util.concurrent.TimeUnit;

@Slf4j
@Component
public class LoginRateLimiter {

    private static final int MAX_ATTEMPTS_PER_WINDOW = 5;
    private static final long WINDOW_MS = 300000;
    private static final String KEY_PREFIX = "login:fail:";

    private final StringRedisTemplate redisTemplate;

    public LoginRateLimiter(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public boolean isBlocked(String identifier) {
        String count = redisTemplate.opsForValue().get(KEY_PREFIX + identifier);
        if (count == null) return false;
        return Integer.parseInt(count) >= MAX_ATTEMPTS_PER_WINDOW;
    }

    public void recordFailure(String identifier) {
        String key = KEY_PREFIX + identifier;
        Long count = redisTemplate.opsForValue().increment(key);
        if (count != null && count == 1) {
            redisTemplate.expire(key, WINDOW_MS, TimeUnit.MILLISECONDS);
        }
        log.warn("Login attempt recorded for: {}. Failed attempts: {}", identifier, count);
    }

    public void recordSuccess(String identifier) {
        redisTemplate.delete(KEY_PREFIX + identifier);
    }

    public void reset(String identifier) {
        redisTemplate.delete(KEY_PREFIX + identifier);
    }
}
