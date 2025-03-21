package com.thales.security.config;

import com.thales.security.filter.JwtAuthenticationFilter;
import com.thales.security.service.JwksService;
import com.thales.security.service.JwtTokenService;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.util.StringUtils;

/**
 * Auto-configuration class for JWT security configuration.
 * This class automatically adds JWT security features to Spring Boot applications.
 */
@Configuration
@EnableWebSecurity
@EnableScheduling
@RequiredArgsConstructor
@ComponentScan("com.thales.security")
@EnableConfigurationProperties(JwtSecurityProperties.class)
@ConditionalOnProperty(prefix = "jwt.security", name = "enabled", havingValue = "true", matchIfMissing = true)
@Slf4j
public class JwtSecurityAutoConfiguration {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final JwtSecurityProperties securityProperties;

    @PostConstruct
    public void init() {
        if (!StringUtils.hasText(securityProperties.getJwksUrl())) {
            log.error("JWKS URL is not configured. Please set jwt.security.jwks-url in application.properties");
            throw new IllegalStateException("JWKS URL must be configured with jwt.security.jwks-url property");
        }
        log.info("JWT Security initialized with JWKS URL: {}", securityProperties.getJwksUrl());
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        
        return http.build();
    }

    @Bean
    public JwtTokenService jwtTokenService(JwksService jwksService) {
        return new JwtTokenService(jwksService);
    }
    
    @Bean
    public JwksService jwksService() {
        return new JwksService(securityProperties);
    }
} 