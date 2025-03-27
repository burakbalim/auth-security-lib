package com.thales.security.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * Class that holds user information from JWT token.
 * This class stores information extracted from the token.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class JwtUserClaims {

    private Long userId;
    private String subject;
    private String username;
    private String email;
    private List<String> roles;
    private Long expirationTime;

    // More fields can be added as needed
}
