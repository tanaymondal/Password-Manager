package com.securevault.config;

import com.securevault.util.ClientIpResolver;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.UUID;

@Slf4j
@Component
@RequiredArgsConstructor
public class RequestLoggingInterceptor implements HandlerInterceptor {

    private final ClientIpResolver clientIpResolver;

    private static final String START_TIME = "startTime";
    private static final String REQUEST_ID = "requestId";

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        String requestId = UUID.randomUUID().toString().substring(0, 8);
        request.setAttribute(REQUEST_ID, requestId);
        request.setAttribute(START_TIME, System.currentTimeMillis());

        String ip = clientIpResolver.getClientIp(request);
        String ua = request.getHeader("User-Agent");
        log.info("[{}] {} {} - IP: {}, UA: {}",
                requestId,
                request.getMethod(),
                request.getRequestURI(),
                maskIp(ip),
                ua != null && ua.length() > 60 ? ua.substring(0, 60) + "..." : ua);

        return true;
    }

    @Override
    public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler, ModelAndView modelAndView) {
    }

    private String maskIp(String ip) {
        if (ip == null || ip.isBlank()) return "unknown";
        if (ip.contains(".")) {
            int lastDot = ip.lastIndexOf('.');
            return ip.substring(0, lastDot) + ".h:"
                + HexFormat.of().formatHex(sha256(ip)).substring(0, 8);
        }
        return "ip:h:" + HexFormat.of().formatHex(sha256(ip)).substring(0, 8);
    }

    private byte[] sha256(String input) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(input.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            return new byte[32];
        }
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) {
        long startTime = (Long) request.getAttribute(START_TIME);
        String requestId = (String) request.getAttribute(REQUEST_ID);
        long duration = System.currentTimeMillis() - startTime;

        if (ex != null) {
            log.error("[{}] {} {} - {} ({}ms)",
                    requestId,
                    request.getMethod(),
                    request.getRequestURI(),
                    ex.getMessage(),
                    duration);
        } else {
            log.info("[{}] {} {} - {} ({}ms)",
                    requestId,
                    request.getMethod(),
                    request.getRequestURI(),
                    response.getStatus(),
                    duration);
        }
    }
}