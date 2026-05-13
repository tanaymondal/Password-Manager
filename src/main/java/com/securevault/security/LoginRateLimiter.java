package com.securevault.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Rate limiter for login attempts to prevent brute-force attacks.
 *
 * This component tracks failed login attempts per identifier (IP or email)
 * and blocks further attempts after reaching a threshold within a time window.
 *
 * HOW IT WORKS:
 * - Uses a sliding window algorithm (5 minutes)
 * - Tracks failed attempts per identifier in buckets
 * - After 5 failures in 5 minutes, blocks that identifier
 * - Blocks are automatically lifted after the window expires
 *
 * CONFIGURATION:
 * - MAX_ATTEMPTS_PER_WINDOW: 5 attempts allowed
 * - WINDOW_MS: 5 minutes (300000ms)
 *
 * SECURITY:
 * - Prevents brute-force password guessing
 * - Per-identifier tracking (can track by IP or email)
 * - Thread-safe using ConcurrentHashMap and AtomicInteger
 *
 * NOTE: This is a simple in-memory implementation. For production,
 * use Redis or a distributed cache for multi-instance deployments.
 */
@Slf4j
@Component
public class LoginRateLimiter {

    private static final int MAX_ATTEMPTS_PER_WINDOW = 5;
    private static final long WINDOW_MS = 300000;

    private final Map<String, LoginAttemptBucket> buckets = new ConcurrentHashMap<>();

    /**
     * Checks if an identifier is currently blocked.
     *
     * @param identifier IP address or email being checked
     * @return true if blocked, false otherwise
     */
    public boolean isBlocked(String identifier) {
        LoginAttemptBucket bucket = buckets.computeIfAbsent(identifier, k -> new LoginAttemptBucket());
        return bucket.isBlocked();
    }

    /**
     * Records a failed login attempt for an identifier.
     *
     * @param identifier IP address or email that failed
     */
    public void recordFailure(String identifier) {
        LoginAttemptBucket bucket = buckets.computeIfAbsent(identifier, k -> new LoginAttemptBucket());
        bucket.recordFailure();
        log.warn("Login attempt recorded for: {}. Failed attempts: {}", identifier, bucket.getAttemptCount());
    }

    /**
     * Records a successful login, clearing the failure bucket.
     *
     * @param identifier IP address or email that succeeded
     */
    public void recordSuccess(String identifier) {
        buckets.remove(identifier);
    }

    /**
     * Manually resets the failure count for an identifier.
     *
     * @param identifier IP address or email to reset
     */
    public void reset(String identifier) {
        buckets.remove(identifier);
    }

    /**
     * Internal bucket for tracking attempts within a time window.
     */
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