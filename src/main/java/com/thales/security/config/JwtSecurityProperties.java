package com.thales.security.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Properties class for JWT security configuration.
 * This class can be configured from application.yml or application.properties file
 * with the jwt.security prefix.
 */
@Data
@ConfigurationProperties(prefix = "jwt.security")
public class JwtSecurityProperties {
    
    /**
     * Whether JWT security features are enabled.
     */
    private boolean enabled = true;
    
    /**
     * JWT signing key (for HMAC).
     * @deprecated This value is not used when JwksUrl property is used.
     */
    @Deprecated
    private String secret = "defaultSecretKeyIfNotProvidedMakeThisLongEnoughForHMAC";
    
    /**
     * JWKS endpoint URL.
     * Public keys for JWT token validation are obtained from this URL.
     * This must be configured in application.properties or application.yml.
     */
    private String jwksUrl;
} 