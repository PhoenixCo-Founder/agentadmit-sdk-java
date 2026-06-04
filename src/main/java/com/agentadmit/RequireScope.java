package com.agentadmit;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation to enforce a required scope on a controller method.
 * The agent must have the specified scope or a 403 Forbidden response is returned.
 *
 * <p>Usage:
 * <pre>{@code
 * @GetMapping("/api/orders")
 * @RequireScope("read:orders")
 * public List<Order> getOrders() { ... }
 * }</pre>
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface RequireScope {
    /**
     * The scope string required for this endpoint.
     * @return the required scope
     */
    String value();
}
