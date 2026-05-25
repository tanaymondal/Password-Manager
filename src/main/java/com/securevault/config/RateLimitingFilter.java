package com.securevault.config;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

@Slf4j
@Component
@Order(2)
public class RateLimitingFilter implements Filter {

    private final Map<String, RateLimitBucket> buckets = new ConcurrentHashMap<>();
    private final ScheduledExecutorService cleanupScheduler = Executors.newSingleThreadScheduledExecutor();

    @Value("${app.rate-limit.requests-per-minute:60}")
    private int maxRequestsPerMinute;

    @PostConstruct
    public void init() {
        cleanupScheduler.scheduleAtFixedRate(this::evictStaleBuckets, 60, 60, TimeUnit.SECONDS);
    }

    @PreDestroy
    public void destroy() {
        cleanupScheduler.shutdownNow();
    }

    private void evictStaleBuckets() {
        long now = System.currentTimeMillis();
        buckets.values().removeIf(bucket -> now - bucket.getWindowStart() > 120_000);
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        String path = httpRequest.getRequestURI();
        if (path.startsWith("/swagger-ui") || path.startsWith("/v3/api-docs") || path.equals("/swagger-ui.html")) {
            chain.doFilter(request, response);
            return;
        }

        String clientId = getClientIdentifier(httpRequest);
        RateLimitBucket bucket = buckets.computeIfAbsent(clientId, k -> new RateLimitBucket(maxRequestsPerMinute));

        if (bucket.tryConsume()) {
            httpResponse.setHeader("X-RateLimit-Remaining", String.valueOf(bucket.getRemaining()));
            chain.doFilter(request, response);
        } else {
            log.warn("Rate limit exceeded for client: {}", clientId);
            httpResponse.setStatus(429);
            httpResponse.setContentType("application/json");
            httpResponse.getWriter().write("{\"success\":false,\"message\":\"Rate limit exceeded. Please try again later.\"}");
        }
    }

    private String getClientIdentifier(HttpServletRequest request) {
        return request.getRemoteAddr();
    }

    private static class RateLimitBucket {
        private final int maxRequests;
        private final AtomicInteger count = new AtomicInteger(0);
        private volatile long windowStart = System.currentTimeMillis();

        RateLimitBucket(int maxRequests) {
            this.maxRequests = maxRequests;
        }

        long getWindowStart() {
            return windowStart;
        }

        synchronized boolean tryConsume() {
            long now = System.currentTimeMillis();
            if (now - windowStart > 60000) {
                windowStart = now;
                count.set(0);
            }
            if (count.get() < maxRequests) {
                count.incrementAndGet();
                return true;
            }
            return false;
        }

        int getRemaining() {
            return Math.max(0, maxRequests - count.get());
        }
    }
}