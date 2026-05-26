package com.securevault.security;

import com.securevault.entity.User;
import com.securevault.repository.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.UUID;

/**
 * Spring Security filter that extracts and validates JWT tokens from HTTP requests.
 *
 * This filter runs on every request and:
 * 1. Extracts the JWT token from the Authorization header
 * 2. Validates the token signature and expiration
 * 3. Loads user details from the email claim
 * 4. Sets the Spring Security authentication context
 *
 * REQUEST FLOW:
 * Request -> JwtAuthenticationFilter -> [Valid Token] -> SecurityContext -> Controller
 *                           -> [No/Invalid Token] -> Unauthenticated -> Controller
 *
 * SECURITY:
 * - Validates token signature (prevents tampering)
 * - Checks token expiration (prevents replay with expired tokens)
 * - Uses constant-time token extraction (prevents timing attacks)
 * - Sets authentication on successful validation only
 *
 * @see JwtTokenProvider for token validation logic
 * @see CustomUserDetailsService for user loading
 */
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;
    private final CustomUserDetailsService userDetailsService;
    private final UserRepository userRepository;

    /**
     * Processes each HTTP request to extract and validate JWT token.
     *
     * If a valid token is found, the user is authenticated in the SecurityContext.
     * If no token or invalid token, the request continues unauthenticated.
     *
     * @param request Current HTTP request
     * @param response Current HTTP response
     * @param filterChain Next filter in the chain
     * @throws ServletException if filter processing fails
     * @throws IOException if I/O error occurs
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String token = getTokenFromRequest(request);

        if (StringUtils.hasText(token) && jwtTokenProvider.validateToken(token)) {
            UUID userId = jwtTokenProvider.getUserIdFromToken(token);

            User user = userRepository.findById(userId).orElse(null);
            if (user != null) {
                Object tokenPwdClaim = jwtTokenProvider.getClaim(token, "pwdUpdatedAt", Object.class);
                LocalDateTime dbPwdUpdatedAt = user.getPasswordUpdatedAt();

                if (dbPwdUpdatedAt != null && tokenPwdClaim instanceof Number) {
                    long tokenPwdUpdatedAt = ((Number) tokenPwdClaim).longValue();
                    if (tokenPwdUpdatedAt != dbPwdUpdatedAt.toEpochSecond(ZoneOffset.UTC)) {
                        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                        response.setContentType("application/json");
                        response.getWriter().write(
                            "{\"success\":false,\"message\":\"Password changed on another device. Please re-login.\"}"
                        );
                        return;
                    }
                }

                String email = jwtTokenProvider.getEmailFromToken(token);
                UserDetails userDetails = userDetailsService.loadUserByUsername(email);

                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Extracts JWT token from the Authorization header.
     *
     * Looks for header: "Authorization: Bearer <token>"
     *
     * @param request HTTP request
     * @return Token string without "Bearer " prefix, or null if not present
     */
    private String getTokenFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}