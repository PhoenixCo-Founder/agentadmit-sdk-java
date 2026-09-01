package com.agentadmit;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Resolves the single required scope that will be enforced for an inbound
 * request, BEFORE the introspection call is made, so {@link AgentAdmitFilter}
 * can declare it as {@code scope_used} on the verify request body
 * (per-call audit telemetry).
 *
 * <p>The default implementation, {@link HandlerMappingScopeResolver}, reads
 * the {@link RequireScope} / {@link RequireScopeIfAgent} annotation off the
 * Spring MVC handler method mapped to the request — the same annotation
 * {@link ScopeEnforcementAspect} enforces after the filter runs.
 */
@FunctionalInterface
public interface RequiredScopeResolver {

    /**
     * Resolve the single scope that will be enforced for this request.
     *
     * <p>Telemetry must never block verification: implementations should
     * return {@code null} rather than throw when the scope cannot be
     * determined (the {@code scope_used} field is then omitted).
     *
     * @param request the inbound request
     * @return the single required scope, or {@code null} when no single scope is known
     */
    String resolveRequiredScope(HttpServletRequest request);
}
