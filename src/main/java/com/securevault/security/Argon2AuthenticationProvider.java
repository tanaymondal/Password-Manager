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

@Component
@RequiredArgsConstructor
public class Argon2AuthenticationProvider implements AuthenticationProvider {

    private final UserRepository userRepository;
    private final PasswordService passwordService;

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

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}