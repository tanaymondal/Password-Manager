package com.securevault.security;

import com.securevault.entity.User;
import com.securevault.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * Spring Security UserDetailsService implementation for loading user data.
 *
 * This service bridges the database User entity with Spring Security's
 * authentication system. It is used by JwtAuthenticationFilter to load
 * user details after validating a JWT token.
 *
 * SECURITY:
 * - Throws UsernameNotFoundException for non-existent users
 * - Returns CustomUserDetails with user ID, email, and password hash
 * - Used only after JWT validation (not for direct password authentication)
 *
 * @see CustomUserDetails for the UserDetails implementation
 * @see JwtAuthenticationFilter for the filter that uses this service
 */
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    /**
     * Loads user by email address for Spring Security authentication.
     *
     * @param email User's email address (used as username)
     * @return UserDetails implementation for the user
     * @throws UsernameNotFoundException if no user exists with the given email
     */
    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + email));
        return new CustomUserDetails(user);
    }
}