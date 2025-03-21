package com.thales.security.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.thales.security.model.JwtUserClaims;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Base64;
import java.nio.charset.StandardCharsets;

/**
 * Service class for JWT token operations.
 * This class performs JWT token validation and extraction of information from tokens.
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class JwtTokenService {

    private final JwksService jwksService;

    /**
     * Validates the token and extracts its information.
     *
     * @param token JWT token to be validated
     * @return User information from the token, returns null if token is invalid
     */
    public JwtUserClaims validateAndExtractClaims(String token) {
        try {
            // First decode the header part of the token (without validation)
            String kid = extractKidFromToken(token);
            if (kid == null) {
                log.error("No kid (Key ID) found in JWT token");
                return null;
            }
            
            // Get the public key for the kid from the JWKS service
            PublicKey publicKey = jwksService.getPublicKey(kid);
            if (publicKey == null) {
                log.error("No public key found for kid: {}", kid);
                return null;
            }
            
            // Validate the token with the public key
            Jws<Claims> claimsJws = Jwts.parserBuilder()
                    .setSigningKey(publicKey)
                    .build()
                    .parseClaimsJws(token);
            
            Claims claims = claimsJws.getBody();
            
            return mapClaimsToUser(claims);
        } catch (ExpiredJwtException e) {
            log.warn("JWT token has expired: {}", e.getMessage());
        } catch (JwtException e) {
            log.error("JWT token is invalid: {}", e.getMessage());
        } catch (Exception e) {
            log.error("JWT validation error: {}", e.getMessage());
        }
        return null;
    }

    /**
     * Extracts the Key ID (kid) from the JWT token header.
     *
     * @param token JWT token
     * @return Key ID (kid)
     */
    public String extractKidFromToken(String token) {
        try {
            // Get header part from JWT token
            String header = token.split("\\.")[0];
            
            // Decode from Base64
            byte[] decodedHeader = Base64.getDecoder().decode(header);
            String headerJson = new String(decodedHeader, StandardCharsets.UTF_8);
            
            // Parse JSON and extract kid
            JsonNode jsonNode = jwksService.getObjectMapper().readTree(headerJson);
            return jsonNode.get("kid").asText();
        } catch (Exception e) {
            log.error("Kid extraction error: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Converts claims from token into JwtUserClaims object.
     *
     * @param claims Claims information from JWT token
     * @return JwtUserClaims object
     */
    @SuppressWarnings("unchecked")
    private JwtUserClaims mapClaimsToUser(Claims claims) {
        List<String> roles = claims.get("roles", List.class);
        if (roles == null) {
            roles = new ArrayList<>();
        }
        
        return JwtUserClaims.builder()
                .userId(claims.getSubject())
                .username(claims.get("username", String.class))
                .email(claims.get("email", String.class))
                .roles(roles)
                .expirationTime(claims.getExpiration().getTime())
                .build();
    }

    /**
     * Extracts the Bearer token from Authorization header.
     *
     * @param authorizationHeader Authorization header value
     * @return JWT token, null if header is empty or not in correct format
     */
    public String extractTokenFromHeader(String authorizationHeader) {
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            return authorizationHeader.substring(7);
        }
        return null;
    }
} 