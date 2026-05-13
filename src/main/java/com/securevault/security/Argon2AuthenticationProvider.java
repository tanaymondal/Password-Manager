package com.securevault.security;

import com.securevault.entity.User;
import com.securevault.repository.UserRepository;
import com.securevault.service.PasswordService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.Collections;

/**
 * Spring Security AuthenticationProvider that uses Argon2id for password verification.
 *
 * This provider is used for form-based login authentication. It:
 * 1. Extracts email and password from the authentication token
 * 2. Looks up the user in the database
 * 3. Checks if the account is locked
 * 4. Verifies the password using Argon2id via PasswordService
 * 5. Returns an authenticated token if successful
 *
 * SECURITY:
 * - Uses Argon2id (memory-hard, GPU-resistant)
 * - Checks account lock status before authentication
 * - Returns authenticated token with user details
 *
 * @see PasswordService for Argon2id password verification
 */
@Component
@RequiredArgsConstructor
public class Argon2AuthenticationProvider implements AuthenticationProvider {

    private final UserRepository userRepository;
    private final PasswordService passwordService;

    /**
     * Authenticates a user with email and password.
     *
     * @param authentication Contains email (name) and password (credentials)
     * @return Authenticated token with UserDetails if successful
     * @throws UsernameNotFoundException if user not found
     * @throws BadCredentialsException if password is wrong or account is locked
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String email = authentication.getName();
        String password = authentication.getCredentials().toString();

        User user = userRepository.findByEmail(email.toLowerCase().trim())
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        if (user.isLocked()) {
            throw new BadCredentialsException("Account is temporarily locked");
        }

        if (!passwordService.verifyPassword(password, user.getPasswordSalt(), user.getPasswordHash())) {
            throw new BadCredentialsException("Invalid credentials");
        }

        UserDetails userDetails = new CustomUserDetails(user);
        return new UsernamePasswordAuthenticationToken(userDetails, password, Collections.emptyList());
    }

    /**
     * Checks if this provider supports the given authentication type.
     *
     * @param authentication Class to check
     * @return true if UsernamePasswordAuthenticationToken
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}