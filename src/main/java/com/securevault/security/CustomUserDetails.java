package com.securevault.security;

import com.securevault.entity.User;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;
import java.util.UUID;

/**
 * Custom UserDetails implementation that wraps a User entity.
 *
 * This class adapts the database User entity to Spring Security's UserDetails
 * interface. It is used after JWT token validation to provide user information
 * to the Spring Security context.
 *
 * SECURITY:
 * - Contains user ID, email, and password hash (not plaintext password)
 * - Implements all UserDetails methods for Spring Security compatibility
 * - Returns empty authorities (role-based auth not used in this app)
 *
 * @see CustomUserDetailsService for loading this from the database
 * @see JwtAuthenticationFilter for setting this in SecurityContext
 */
@Getter
public class CustomUserDetails implements UserDetails {

    private final UUID id;
    private final String email;
    private final String password;

    /**
     * Creates CustomUserDetails from a User entity.
     *
     * @param user Database user entity
     */
    public CustomUserDetails(User user) {
        this.id = user.getId();
        this.email = user.getEmail();
        this.password = user.getPasswordHash();
    }

    /**
     * Returns user authorities (empty - role-based auth not used).
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.emptyList();
    }

    /**
     * Returns the password hash (not plaintext password).
     */
    @Override
    public String getPassword() {
        return password;
    }

    /**
     * Returns the email address as the username.
     */
    @Override
    public String getUsername() {
        return email;
    }

    /**
     * Account never expires.
     */
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    /**
     * Account is not locked (lock status is checked separately in AuthService).
     */
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    /**
     * Credentials never expire.
     */
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    /**
     * User account is always enabled.
     */
    @Override
    public boolean isEnabled() {
        return true;
    }
}