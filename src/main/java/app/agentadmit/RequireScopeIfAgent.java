package app.agentadmit;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation to enforce scope only for agent tokens.
 * Regular user requests pass through without scope enforcement.
 *
 * Usage:
 *   @GetMapping("/api/profile")
 *   @RequireScopeIfAgent("read:profile")
 *   public UserProfile getProfile() { ... }
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface RequireScopeIfAgent {
    String value();
}
