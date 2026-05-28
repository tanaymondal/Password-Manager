package com.securevault.security;

import com.securevault.util.UserUtils;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

@Slf4j
@Aspect
@Component
@RequiredArgsConstructor
public class SudoAspect {

    private final SudoService sudoService;

    @Around("@annotation(requireSudo)")
    public Object checkSudo(ProceedingJoinPoint joinPoint, RequireSudo requireSudo) throws Throwable {
        ServletRequestAttributes attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (attrs == null) {
            throw new SecurityException("Sudo required but no request context available");
        }

        HttpServletRequest request = attrs.getRequest();
        String sudoToken = request.getHeader("X-Sudo-Token");
        if (sudoToken == null || sudoToken.isBlank()) {
            sudoToken = request.getParameter("sudo_token");
        }

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated() || !(auth.getPrincipal() instanceof UserDetails userDetails)) {
            throw new SecurityException("Authentication required for sudo-protected operation");
        }

        java.util.UUID userId = UserUtils.getUserId(userDetails);

        if (!sudoService.validateSudoToken(userId, sudoToken)) {
            log.warn("Sudo validation failed for user: {}", userId);
            throw new SecurityException("Sudo token required or expired. Please re-authenticate.");
        }

        sudoService.consumeSudoToken(userId, sudoToken);
        return joinPoint.proceed();
    }
}
