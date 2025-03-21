package com.thales.security.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.thales.security.config.JwtSecurityProperties;
import io.jsonwebtoken.security.InvalidKeyException;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Service class for JWKS (JSON Web Key Set) operations.
 * This class retrieves public keys from JWKS endpoint for JWT validation.
 */
@Service
@Slf4j
public class JwksService {

    private final RestTemplate restTemplate;
    /**
     * -- GETTER --
     *  Gets the ObjectMapper instance.
     *
     */
    @Getter
    private final ObjectMapper objectMapper;
    private final Map<String, PublicKey> keyCache = new ConcurrentHashMap<>();
    private final JwtSecurityProperties securityProperties;

    @Autowired
    public JwksService(JwtSecurityProperties securityProperties) {
        this.securityProperties = securityProperties;
        this.restTemplate = new RestTemplate();
        this.objectMapper = new ObjectMapper();
        // Load keys when application starts
        refreshKeys();
    }

    /**
     * Gets the public key for a specific kid (Key ID).
     *
     * @param kid Key ID
     * @return PublicKey object, null if not found
     */
    public PublicKey getPublicKey(String kid) {
        if (keyCache.containsKey(kid)) {
            return keyCache.get(kid);
        }

        // If key is not in cache, refresh and try again
        refreshKeys();
        return keyCache.get(kid);
    }

    /**
     * Retrieves all public keys from JWKS endpoint and caches them.
     * Runs automatically every 12 hours.
     */
    @Scheduled(fixedRate = 12 * 60 * 60 * 1000) // 12 hours
    public void refreshKeys() {
        try {
            String jwksUrl = securityProperties.getJwksUrl();
            if (jwksUrl == null || jwksUrl.isEmpty()) {
                log.error("JWKS URL is not configured. Please set jwt.security.jwks-url in application.properties");
                return;
            }

            log.debug("Refreshing JWKS keys. URL: {}", jwksUrl);
            String jwksJson = restTemplate.getForObject(jwksUrl, String.class);
            JsonNode jwks = objectMapper.readTree(jwksJson);
            JsonNode keys = jwks.get("keys");

            if (keys.isArray()) {
                for (JsonNode key : keys) {
                    if ("RSA".equals(key.get("kty").asText()) && "sig".equals(key.get("use").asText())) {
                        String kid = key.get("kid").asText();
                        String modulus = key.get("n").asText();
                        String exponent = key.get("e").asText();

                        try {
                            PublicKey publicKey = createPublicKey(modulus, exponent);
                            keyCache.put(kid, publicKey);
                            log.debug("Public key successfully added: {}", kid);
                        } catch (Exception e) {
                            log.error("Public key creation error (kid: {}): {}", kid, e.getMessage());
                        }
                    }
                }
            }
        } catch (Exception e) {
            log.error("JWKS refresh error: {}", e.getMessage());
        }
    }

    /**
     * Creates an RSA public key.
     *
     * @param modulus Base64URL encoded modulus
     * @param exponent Base64URL encoded exponent
     * @return RSA PublicKey object
     */
    private PublicKey createPublicKey(String modulus, String exponent) throws Exception {
        try {
            // Base64URL to BigInteger
            byte[] modulusBytes = Base64.getUrlDecoder().decode(modulus);
            byte[] exponentBytes = Base64.getUrlDecoder().decode(exponent);

            BigInteger modulusBigInt = new BigInteger(1, modulusBytes);
            BigInteger exponentBigInt = new BigInteger(1, exponentBytes);

            RSAPublicKeySpec spec = new RSAPublicKeySpec(modulusBigInt, exponentBigInt);
            KeyFactory factory = KeyFactory.getInstance("RSA");
            return factory.generatePublic(spec);
        } catch (Exception e) {
            throw new InvalidKeyException("Could not create public key: " + e.getMessage());
        }
    }
}
