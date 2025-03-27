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
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * JWT Authentication Filter.
 * This filter validates JWT token in every HTTP request and places user information in thread-safe context.
 */
@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String UNAUTHORIZED_ERROR_MESSAGE = "Invalid or expired JWT token";
    private static final DateTimeFormatter DATE_TIME_FORMATTER = DateTimeFormatter.ISO_DATE_TIME;
    private static final String OPTIONS_METHOD = "OPTIONS";
    
    private final JwtTokenService jwtTokenService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        try {
            if (shouldSkipAuthentication(request)) {
                proceedWithFilterChain(request, response, filterChain);
                return;
            }

            if (!authenticateRequest(request, response)) {
                return; // Response is already set by authenticateRequest
            }

            proceedWithFilterChain(request, response, filterChain);
        } finally {
            clearSecurityContexts();
        }
    }

    /**
     * Determines if authentication should be skipped for this request
     *
     * @param request HTTP request
     * @return true if authentication should be skipped
     */
    private boolean shouldSkipAuthentication(HttpServletRequest request) {
        return isPreflightRequest(request);
    }

    /**
     * Authenticates the request if an authorization header is present
     *
     * @param request HTTP request
     * @param response HTTP response
     * @return true if authenticated or no auth header, false if authentication failed
     * @throws IOException if writing to the response fails
     */
    private boolean authenticateRequest(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String authorizationHeader = request.getHeader(AUTHORIZATION_HEADER);
        
        if (isHeaderEmpty(authorizationHeader)) {
            return true; // No auth header, not our concern
        }

        return processAuthHeader(authorizationHeader, request, response);
    }

    /**
     * Checks if the authorization header is empty or null
     *
     * @param authorizationHeader Authorization header
     * @return true if header is empty or null
     */
    private boolean isHeaderEmpty(String authorizationHeader) {
        return authorizationHeader == null || authorizationHeader.isEmpty();
    }

    /**
     * Processes the authorization header and attempts to authenticate
     *
     * @param authorizationHeader Authorization header
     * @param request HTTP request
     * @param response HTTP response
     * @return true if successfully authenticated, false otherwise
     * @throws IOException if writing to the response fails
     */
    private boolean processAuthHeader(String authorizationHeader, HttpServletRequest request, HttpServletResponse response) 
            throws IOException {
        try {
            boolean authenticated = processJwtAuthentication(authorizationHeader, request);
            if (!authenticated) {
                sendUnauthorizedResponse(response);
                return false;
            }
            return true;
        } catch (Exception e) {
            handleAuthenticationException(e, response);
            return false;
        }
    }

    /**
     * Proceeds with the filter chain
     *
     * @param request HTTP request
     * @param response HTTP response
     * @param filterChain Filter chain
     * @throws ServletException if a servlet exception occurs
     * @throws IOException if an I/O error occurs
     */
    private void proceedWithFilterChain(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) 
            throws ServletException, IOException {
        filterChain.doFilter(request, response);
    }

    /**
     * Handles authentication exceptions
     *
     * @param e Exception that occurred
     * @param response HTTP response
     * @throws IOException if writing to the response fails
     */
    private void handleAuthenticationException(Exception e, HttpServletResponse response) throws IOException {
        log.error("Authentication error: {}", e.getMessage(), e);
        sendUnauthorizedResponse(response);
    }

    /**
     * Checks if the request is a CORS preflight request
     * 
     * @param request HTTP request
     * @return True if it's a preflight request
     */
    private boolean isPreflightRequest(HttpServletRequest request) {
        return OPTIONS_METHOD.equals(request.getMethod());
    }

    /**
     * Processes JWT token and sets authentication information if valid
     * 
     * @param authorizationHeader Authorization header
     * @param request HTTP request
     * @return True if authentication succeeded, false otherwise
     */
    private boolean processJwtAuthentication(String authorizationHeader, HttpServletRequest request) {
        String token = jwtTokenService.extractTokenFromHeader(authorizationHeader);
        if (token == null) {
            log.debug("No token found in authorization header");
            return false;
        }
        
        JwtUserClaims userClaims = jwtTokenService.validateAndExtractClaims(token);
        if (userClaims == null) {
            log.debug("Invalid token or failed to extract claims");
            return false;
        }
        
        setupSecurityContexts(userClaims, request);
        return true;
    }

    /**
     * Sets up user information in security contexts
     * 
     * @param userClaims User claims information
     * @param request HTTP request
     */
    private void setupSecurityContexts(JwtUserClaims userClaims, HttpServletRequest request) {
        // Place user information in JwtSecurityContext
        JwtSecurityContext.setCurrentUser(userClaims);
        log.debug("JWT token validated and user information placed in context: {}", userClaims);

        // Create Spring Security Authentication object and set it in SecurityContextHolder
        setupSpringSecurityContext(userClaims, request);
    }

    /**
     * Sets up Spring Security context with user information
     * 
     * @param userClaims User claims information
     * @param request HTTP request
     */
    private void setupSpringSecurityContext(JwtUserClaims userClaims, HttpServletRequest request) {
        Collection<SimpleGrantedAuthority> authorities = extractAuthorities(userClaims);
        
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                userClaims.getUsername(), null, authorities);
        
        // Add request details to authentication
        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        
        SecurityContextHolder.getContext().setAuthentication(authentication);
        log.debug("Spring Security Authentication object created and set in SecurityContextHolder");
    }

    /**
     * Extracts authorities from user roles
     * 
     * @param userClaims User claims information
     * @return Collection of authorities
     */
    private Collection<SimpleGrantedAuthority> extractAuthorities(JwtUserClaims userClaims) {
        List<String> roles = userClaims.getRoles();
        if (roles == null || roles.isEmpty()) {
            return Collections.emptyList();
        }
        
        return roles.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }

    /**
     * Sends 401 Unauthorized response
     *
     * @param response HTTP response
     * @throws IOException If an I/O error occurs
     */
    private void sendUnauthorizedResponse(HttpServletResponse response) throws IOException {
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType("application/json");
        
        String timestamp = LocalDateTime.now().format(DATE_TIME_FORMATTER);
        String errorJson = String.format(
                "{\"status\":%d,\"message\":\"%s\",\"timestamp\":\"%s\"}",
                HttpStatus.UNAUTHORIZED.value(),
                UNAUTHORIZED_ERROR_MESSAGE,
                timestamp
        );
        
        response.getWriter().write(errorJson);
    }

    /**
     * Clears all security contexts
     */
    private void clearSecurityContexts() {
        JwtSecurityContext.clear();
        SecurityContextHolder.clearContext();
    }
}
