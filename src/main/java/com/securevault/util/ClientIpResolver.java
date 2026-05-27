package com.securevault.util;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class ClientIpResolver {

    private final boolean proxyTrusted;

    public ClientIpResolver(@Value("${app.proxy.trusted:false}") boolean proxyTrusted) {
        this.proxyTrusted = proxyTrusted;
    }

    public String getClientIp(HttpServletRequest request) {
        if (proxyTrusted) {
            String xff = request.getHeader("X-Forwarded-For");
            if (xff != null && !xff.isBlank()) {
                return xff.split(",")[0].trim();
            }
            String xRealIp = request.getHeader("X-Real-IP");
            if (xRealIp != null && !xRealIp.isBlank()) {
                return xRealIp.trim();
            }
        }
        return request.getRemoteAddr();
    }
}
