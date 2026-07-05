package com.agentadmit;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation to enforce human-presence verification on a controller method.
 * The agent's connection must have been authorized by a human who completed
 * a presence ceremony (WebAuthn) on the consent page, or a 403 Forbidden
 * response is returned.
 *
 * <p>Fails closed: connections whose verify response omits the presence
 * block (older servers) or carries {@code verified: false} are rejected.
 *
 * <p>Usage:
 * <pre>{@code
 * @PostMapping("/api/payments")
 * @RequirePresence
 * public Receipt createPayment() { ... }
 * }</pre>
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface RequirePresence {
}
