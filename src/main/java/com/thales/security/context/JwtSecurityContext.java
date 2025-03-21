package com.thales.security.context;

import com.thales.security.model.JwtUserClaims;
import lombok.extern.slf4j.Slf4j;

/**
 * Class that stores user information extracted from JWT token using ThreadLocal
 * in a thread-safe manner.
 */
@Slf4j
public class JwtSecurityContext {

    private static final ThreadLocal<JwtUserClaims> currentUserClaims = new ThreadLocal<>();

    /**
     * Sets the user information to the current thread.
     *
     * @param userClaims User information extracted from JWT token
     */
    public static void setCurrentUser(JwtUserClaims userClaims) {
        currentUserClaims.set(userClaims);
        log.debug("JWT user information added to context: {}", userClaims);
    }

    /**
     * Gets the user information from the current thread.
     *
     * @return User information extracted from JWT token
     */
    public static JwtUserClaims getCurrentUser() {
        return currentUserClaims.get();
    }

    /**
     * Clears the user information in the Thread Local.
     * This method should be called when the thread completes processing the request.
     */
    public static void clear() {
        currentUserClaims.remove();
        log.debug("JWT user information removed from context");
    }
} 