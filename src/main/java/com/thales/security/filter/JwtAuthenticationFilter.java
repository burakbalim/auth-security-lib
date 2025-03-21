package com.thales.security.filter;

import com.thales.security.context.JwtSecurityContext;
import com.thales.security.model.JwtUserClaims;
import com.thales.security.service.JwtTokenService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * JWT Authentication filter.
 * This filter validates JWT token in every HTTP request and places user information in thread-safe context.
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenService jwtTokenService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        try {
            String authorizationHeader = request.getHeader("Authorization");
            String token = jwtTokenService.extractTokenFromHeader(authorizationHeader);

            if (token != null) {
                JwtUserClaims userClaims = jwtTokenService.validateAndExtractClaims(token);
                
                if (userClaims != null) {
                    // If JWT token is valid, place user information in thread-safe context
                    JwtSecurityContext.setCurrentUser(userClaims);
                    log.debug("JWT token validated and user information placed in context: {}", userClaims);
                }
            }
            
            filterChain.doFilter(request, response);
        } finally {
            // Clear context in every case
            JwtSecurityContext.clear();
        }
    }
} 