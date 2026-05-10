package com.securevault.util;

import com.securevault.security.CustomUserDetails;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.UUID;

public class UserUtils {

    public static UUID getUserId(UserDetails userDetails) {
        if (userDetails instanceof CustomUserDetails customUserDetails) {
            return customUserDetails.getId();
        }
        return UUID.fromString(userDetails.getUsername());
    }
}