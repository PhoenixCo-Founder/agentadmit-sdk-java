package com.agentadmit;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Servlet filter that intercepts requests with ag_at_ tokens
 * and validates them via introspection.
 *
 * <p>Where this filter sits in the AgentAdmit flow:
 * <ol>
 *   <li><b>Issue</b> — your backend mints a connection token for a signed-in
 *       user via {@link TokensClient#issueToken(String, java.util.List)}
 *       (duration is tri-state: default 30 days, {@code durationUntilRevoked()},
 *       or explicit seconds). The returned {@code token} ({@code ag_ct_…}) is
 *       handed to the user's agent. It is single-use and short-lived.</li>
 *   <li><b>Exchange</b> — the agent swaps it for an access token via
 *       {@link TokensClient#exchange(String, String, String)} (no API key —
 *       the connection token itself is the credential). The result is an
 *       {@code ag_at_…} access token.</li>
 *   <li><b>Verify</b> — the agent calls your API with
 *       {@code Authorization: Bearer ag_at_…}; THIS filter introspects every
 *       such request through {@link IntrospectionClient} (the billed call)
 *       and exposes the validated identity as request attributes.</li>
 *   <li><b>Revoke</b> — when the user disconnects the agent, call
 *       {@link TokensClient#revoke(String, String)}; subsequent requests on
 *       that connection fail introspection with {@code connection_revoked}.</li>
 * </ol>
 *
 * <p>Sets request attributes for downstream use:
 *   agentadmit.authType  — "agent" or null
 *   agentadmit.userId    — validated user ID
 *   agentadmit.scopes    — granted scopes
 *   agentadmit.connectionId — connection identifier
 *   agentadmit.agentLabel   — agent display name
 *   agentadmit.presence     -- {@link Presence} fact for the connection (null when absent)
 */
@Component
public class AgentAdmitFilter implements Filter {

    private static final Logger logger = LoggerFactory.getLogger(AgentAdmitFilter.class);
    private final AgentAdmitConfig config;
    private final IntrospectionClient introspectionClient;
    private final RequiredScopeResolver scopeResolver;

    /**
     * Construct the filter with required dependencies. The verify call
     * declares {@code endpoint} and {@code method} audit telemetry from the
     * request; {@code scope_used} is omitted because no scope resolver is
     * configured (see {@link #AgentAdmitFilter(AgentAdmitConfig,
     * IntrospectionClient, RequiredScopeResolver)}).
     *
     * @param config               AgentAdmit configuration
     * @param introspectionClient  client used to verify tokens via hosted introspection
     */
    public AgentAdmitFilter(AgentAdmitConfig config, IntrospectionClient introspectionClient) {
        this(config, introspectionClient, null);
    }

    /**
     * Construct the filter with a scope resolver so the verify call can also
     * declare {@code scope_used} — the single scope the route enforces —
     * resolved BEFORE introspection runs. Spring Boot auto-configuration
     * wires a {@link HandlerMappingScopeResolver} that reads
     * {@link RequireScope} / {@link RequireScopeIfAgent} off the mapped
     * handler method.
     *
     * @param config               AgentAdmit configuration
     * @param introspectionClient  client used to verify tokens via hosted introspection
     * @param scopeResolver        resolves the enforced scope for a request, or
     *                             {@code null} to omit {@code scope_used}
     */
    public AgentAdmitFilter(AgentAdmitConfig config, IntrospectionClient introspectionClient,
                            RequiredScopeResolver scopeResolver) {
        this.config = config;
        this.introspectionClient = introspectionClient;
        this.scopeResolver = scopeResolver;
    }

    /**
     * Intercept incoming requests. If the Authorization header carries an AgentAdmit
     * access token ({@code ag_at_} prefix), validate it via introspection and set
     * request attributes for downstream controllers. Invalid tokens receive an
     * immediate error response.
     *
     * {@inheritDoc}
     */
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpReq = (HttpServletRequest) request;
        String auth = httpReq.getHeader("Authorization");

        // RFC 7235: auth-scheme is case-insensitive, so match "bearer" in any
        // casing. The ag_at_ token prefix that follows remains case-sensitive.
        if (auth != null
                && auth.length() > 7
                && auth.substring(0, 7).equalsIgnoreCase("Bearer ")
                && auth.substring(7).startsWith(config.getTokenPrefixAccess())) {
            String token = auth.substring(7); // Remove "Bearer " (any casing)

            try {
                // Per-call audit telemetry: declare the enforced scope (when a
                // resolver can determine it before dispatch), the request path
                // (query string stripped), and the method on the verify call.
                IntrospectionClient.IntrospectionResult result =
                    introspectionClient.verify(token, VerifyTelemetry.forRequest(httpReq, resolveScopeUsed(httpReq)));

                httpReq.setAttribute("agentadmit.authType", "agent");
                httpReq.setAttribute("agentadmit.userId", result.userId());
                httpReq.setAttribute("agentadmit.scopes", result.scopes());
                httpReq.setAttribute("agentadmit.connectionId", result.connectionId());
                httpReq.setAttribute("agentadmit.agentLabel", result.agentLabel());
                httpReq.setAttribute("agentadmit.presence", result.presence());

                logger.debug("AgentAdmit: validated agent token for user={} scopes={}", 
                    result.userId(), result.scopes());

            } catch (AgentAdmitException.ActiveErrorDenial e) {
                // The hosted service refused this call on an active token
                // (e.g. insufficient_scope, bound_exceeded, or an unknown
                // refusal code). Always a 403 denial with the canonical body
                // for the code — never a pass-through, and the chain is NOT
                // continued.
                HttpServletResponse httpResp = (HttpServletResponse) response;
                httpResp.setStatus(e.getStatusCode());
                httpResp.setContentType("application/json");
                httpResp.getWriter().write(e.getResponseBody());
                return;
            } catch (AgentAdmitException e) {
                HttpServletResponse httpResp = (HttpServletResponse) response;
                httpResp.setStatus(e.getStatusCode());
                httpResp.setContentType("application/json");
                httpResp.getWriter().write(
                    "{\"error\":\"" + (e.getStatusCode() == 401 ? "invalid_token" : "introspection_failed") +
                    "\",\"error_description\":\"" + e.getMessage().replace("\"", "\\\"") + "\"}"
                );
                return;
            }
        }

        chain.doFilter(request, response);
    }

    /**
     * Resolve the scope this request's route enforces, for {@code scope_used}
     * telemetry. Returns {@code null} (field omitted) when no resolver is
     * configured or resolution fails — telemetry never blocks verification.
     */
    private String resolveScopeUsed(HttpServletRequest request) {
        if (scopeResolver == null) return null;
        try {
            return scopeResolver.resolveRequiredScope(request);
        } catch (RuntimeException e) {
            logger.debug("AgentAdmit: scope_used resolution failed; omitting from telemetry", e);
            return null;
        }
    }
}
