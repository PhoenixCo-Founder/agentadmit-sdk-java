package com.agentadmit;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerExecutionChain;
import org.springframework.web.servlet.HandlerMapping;

import java.util.function.Supplier;

/**
 * Default {@link RequiredScopeResolver}: asks the Spring MVC
 * {@link HandlerMapping} which handler method the request will dispatch to,
 * and reads the {@link RequireScope} or {@link RequireScopeIfAgent} annotation
 * off that method. This lets {@link AgentAdmitFilter} learn the scope the
 * route enforces BEFORE introspection runs, so the verify call can declare it
 * as {@code scope_used} — even though the filter executes ahead of
 * {@link ScopeEnforcementAspect}.
 *
 * <p>Resolution is telemetry-only and never blocks verification: any lookup
 * failure (no handler mapping in the context, no matching handler, a
 * non-method handler, or an exception from the mapping) resolves to
 * {@code null} and the {@code scope_used} field is simply omitted.
 */
public class HandlerMappingScopeResolver implements RequiredScopeResolver {

    private final Supplier<? extends HandlerMapping> handlerMapping;

    /**
     * Construct the resolver.
     *
     * @param handlerMapping lazily supplies the Spring MVC handler mapping;
     *                       may supply {@code null} when the context has none
     *                       (every request then resolves to {@code null})
     */
    public HandlerMappingScopeResolver(Supplier<? extends HandlerMapping> handlerMapping) {
        this.handlerMapping = handlerMapping;
    }

    /** {@inheritDoc} */
    @Override
    public String resolveRequiredScope(HttpServletRequest request) {
        try {
            HandlerMapping mapping = handlerMapping == null ? null : handlerMapping.get();
            if (mapping == null) return null;
            HandlerExecutionChain chain = mapping.getHandler(request);
            if (chain == null || !(chain.getHandler() instanceof HandlerMethod handlerMethod)) {
                return null;
            }
            RequireScope requireScope = handlerMethod.getMethodAnnotation(RequireScope.class);
            if (requireScope != null) return requireScope.value();
            RequireScopeIfAgent requireScopeIfAgent =
                handlerMethod.getMethodAnnotation(RequireScopeIfAgent.class);
            return requireScopeIfAgent != null ? requireScopeIfAgent.value() : null;
        } catch (Exception e) {
            // Telemetry must never break verification: unresolvable scope is
            // simply not reported.
            return null;
        }
    }
}
