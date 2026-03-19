package app.agentadmit;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation to enforce a required scope on a controller method.
 * Agent must have this scope or a 403 is returned.
 *
 * Usage:
 *   @GetMapping("/api/orders")
 *   @RequireScope("read:orders")
 *   public List<Order> getOrders() { ... }
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface RequireScope {
    String value();
}
