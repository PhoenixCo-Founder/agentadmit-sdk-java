package com.agentadmit;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation to enforce scope only when the request carries an agent token.
 * Regular user requests pass through without scope enforcement.
 *
 * <p>Usage:
 * <pre>{@code
 * @GetMapping("/api/profile")
 * @RequireScopeIfAgent("read:profile")
 * public UserProfile getProfile() { ... }
 * }</pre>
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface RequireScopeIfAgent {
    /**
     * The scope string required when the request is from an agent.
     * @return the required scope
     */
    String value();
}
