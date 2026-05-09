package com.securevault.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

@Slf4j
@Component
public class LoginRateLimiter {

    private static final int MAX_ATTEMPTS_PER_WINDOW = 5;
    private static final long WINDOW_MS = 300000;

    private final Map<String, LoginAttemptBucket> buckets = new ConcurrentHashMap<>();

    public boolean isBlocked(String identifier) {
        LoginAttemptBucket bucket = buckets.computeIfAbsent(identifier, k -> new LoginAttemptBucket());
        return bucket.isBlocked();
    }

    public void recordFailure(String identifier) {
        LoginAttemptBucket bucket = buckets.computeIfAbsent(identifier, k -> new LoginAttemptBucket());
        bucket.recordFailure();
        log.warn("Login attempt recorded for: {}. Failed attempts: {}", identifier, bucket.getAttemptCount());
    }

    public void recordSuccess(String identifier) {
        buckets.remove(identifier);
    }

    public void reset(String identifier) {
        buckets.remove(identifier);
    }

    private static class LoginAttemptBucket {
        private final AtomicInteger attemptCount = new AtomicInteger(0);
        private volatile long windowStart = System.currentTimeMillis();

        synchronized void recordFailure() {
            long now = System.currentTimeMillis();
            if (now - windowStart > WINDOW_MS) {
                windowStart = now;
                attemptCount.set(0);
            }
            attemptCount.incrementAndGet();
        }

        synchronized boolean isBlocked() {
            long now = System.currentTimeMillis();
            if (now - windowStart > WINDOW_MS) {
                windowStart = now;
                attemptCount.set(0);
                return false;
            }
            return attemptCount.get() >= MAX_ATTEMPTS_PER_WINDOW;
        }

        int getAttemptCount() {
            return attemptCount.get();
        }
    }
}