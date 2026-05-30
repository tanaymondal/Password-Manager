package com.securevault.config;

import com.securevault.util.ClientIpResolver;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.Order;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Slf4j
@Component
@Order(2)
public class RateLimitingFilter implements Filter {

    private static final String KEY_PREFIX = "ratelimit:";
    private static final int DEFAULT_LIMIT = 60;
    private static final int AUTH_LIMIT = 20;
    private static final int STRICT_LIMIT = 10;

    private static final Map<String, Integer> ENDPOINT_LIMITS = Map.of(
        "/api/v1/auth/login", AUTH_LIMIT,
        "/api/v1/auth/register", STRICT_LIMIT,
        "/api/v1/auth/prelogin", AUTH_LIMIT,
        "/api/v1/auth/kdf-config", AUTH_LIMIT,
        "/api/v1/auth/verify-2fa", AUTH_LIMIT,
        "/api/v1/auth/refresh", AUTH_LIMIT,
        "/api/v1/auth/sudo", STRICT_LIMIT,
        "/api/v1/auth/logout", STRICT_LIMIT,
        "/api/v1/auth/change-password", STRICT_LIMIT,
        "/api/v1/auth/upgrade-kdf", STRICT_LIMIT,
        "/api/v1/audit", AUTH_LIMIT
    );

    private final StringRedisTemplate redisTemplate;
    private final ClientIpResolver clientIpResolver;
    private final int maxRequestsPerMinute;

    public RateLimitingFilter(StringRedisTemplate redisTemplate,
                              ClientIpResolver clientIpResolver,
                              @Value("${app.rate-limit.requests-per-minute:60}") int maxRequestsPerMinute) {
        this.redisTemplate = redisTemplate;
        this.clientIpResolver = clientIpResolver;
        this.maxRequestsPerMinute = maxRequestsPerMinute;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        if ("OPTIONS".equalsIgnoreCase(httpRequest.getMethod())) {
            chain.doFilter(request, response);
            return;
        }

        String clientId = clientIpResolver.getClientIp(httpRequest);
        String path = httpRequest.getRequestURI();
        int limit = ENDPOINT_LIMITS.getOrDefault(path, maxRequestsPerMinute);
        if (limit < 1) limit = 1;

        String key = KEY_PREFIX + path.replace('/', '_') + ":" + clientId;

        Long count = redisTemplate.opsForValue().increment(key);
        if (count != null && count == 1) {
            redisTemplate.expire(key, 60, TimeUnit.SECONDS);
        }

        if (count != null && count <= limit) {
            httpResponse.setHeader("X-RateLimit-Remaining", String.valueOf(limit - count));
            chain.doFilter(request, response);
        } else {
            log.warn("Rate limit exceeded for {} from {}", path, clientId);
            httpResponse.setStatus(429);
            httpResponse.setContentType("application/json");
            httpResponse.getWriter().write("{\"success\":false,\"message\":\"Rate limit exceeded. Please try again later.\"}");
        }
    }

}
