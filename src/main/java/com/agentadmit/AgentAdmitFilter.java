package com.agentadmit;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.lang.Nullable;
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
 *   agentadmit.actionConfirmation -- {@link ActionConfirmation.Consumed} when the
 *       hosted service spent a confirm-each-time confirmation to allow this call
 *
 * <p><b>Confirm-each-time (1.11.0).</b> The agent's
 * {@value VerifyTelemetry#ACTION_ATTESTATION_HEADER} header is forwarded on
 * every verify call whenever it is present. Configure
 * {@link Options#actionSummary()} on a route group whose scopes are marked
 * {@code confirm_each_time} and the filter also digests the raw request body
 * (still readable by your controller) and sends your plain-language summary,
 * so the hosted confirmation page can commit to the exact action.
 */
@Component
public class AgentAdmitFilter implements Filter {

    private static final Logger logger = LoggerFactory.getLogger(AgentAdmitFilter.class);

    /**
     * Describes THIS action in plain language for the human who has to
     * confirm it ("Pay Alex $50"), for confirm-each-time routes (1.11.0).
     *
     * <p>Receives the inbound request and the RAW request body bytes, already
     * cached — reading them here does not consume the body your controller
     * will read. Return {@code null} or a blank string to send no summary;
     * the value is trimmed and capped at
     * {@value VerifyTelemetry#MAX_ACTION_SUMMARY_LENGTH} characters.
     *
     * <p>The summary is yours: AgentAdmit shows it as the headline of the
     * confirmation page and commits to the text the human saw. It does not
     * verify the text against the request.
     */
    @FunctionalInterface
    public interface ActionSummary {
        /**
         * Describe the action this request performs.
         *
         * @param request the inbound request
         * @param body    the raw request body bytes (empty for a bodyless request)
         * @return the description for the human, or {@code null} for none
         */
        String describe(HttpServletRequest request, byte[] body);
    }

    /**
     * Filter options. All fields are optional; {@link #defaults()} yields the
     * filter's pre-1.11.0 behavior exactly.
     *
     * @param actionSummary describes the action for the human on a
     *        confirm-each-time route. When set, the filter caches and digests
     *        the raw request body and sends {@code request_digest} plus
     *        {@code action_summary} on the verify call. When unset, neither is
     *        sent — but the agent's attestation header is forwarded either way.
     */
    public record Options(ActionSummary actionSummary) {
        /** Options that change nothing: no body digest, no action summary.
         *
         * @return default options
         */
        public static Options defaults() {
            return new Options(null);
        }

        /**
         * Options for a confirm-each-time route group.
         *
         * @param actionSummary describes the action for the human
         * @return options carrying the summary supplier
         */
        public static Options withActionSummary(ActionSummary actionSummary) {
            return new Options(actionSummary);
        }
    }

    private final AgentAdmitConfig config;
    private final IntrospectionClient introspectionClient;
    private final RequiredScopeResolver scopeResolver;
    private final Options options;

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
    @Autowired
    public AgentAdmitFilter(AgentAdmitConfig config, IntrospectionClient introspectionClient,
                            @Nullable RequiredScopeResolver scopeResolver) {
        this(config, introspectionClient, scopeResolver, null);
    }

    /**
     * Construct the filter with confirm-each-time options (1.11.0) in
     * addition to the scope resolver.
     *
     * @param config               AgentAdmit configuration
     * @param introspectionClient  client used to verify tokens via hosted introspection
     * @param scopeResolver        resolves the enforced scope for a request, or
     *                             {@code null} to omit {@code scope_used}
     * @param options              filter options; {@code null} means
     *                             {@link Options#defaults()}
     */
    public AgentAdmitFilter(AgentAdmitConfig config, IntrospectionClient introspectionClient,
                            @Nullable RequiredScopeResolver scopeResolver,
                            @Nullable Options options) {
        this.config = config;
        this.introspectionClient = introspectionClient;
        this.scopeResolver = scopeResolver;
        this.options = options == null ? Options.defaults() : options;
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

            // Confirm-each-time (1.11.0): on a route group with an action
            // summary, cache the body BEFORE reading it so the digest and the
            // downstream controller both see the same bytes. The wrapper is
            // what continues down the chain.
            byte[] body = null;
            if (options.actionSummary() != null) {
                try {
                    CachedBodyHttpServletRequest cached = new CachedBodyHttpServletRequest(httpReq);
                    httpReq = cached;
                    request = cached;
                    body = cached.cachedBody();
                } catch (IOException e) {
                    // Telemetry must never break the call: verify without the
                    // digest and let the body reach the handler untouched.
                    logger.debug("AgentAdmit: request body unavailable for digest; omitting", e);
                }
            }

            try {
                // Per-call audit telemetry: declare the enforced scope (when a
                // resolver can determine it before dispatch), the request path
                // (query string stripped), and the method on the verify call.
                // The agent's attestation header rides along whenever present.
                IntrospectionClient.IntrospectionResult result =
                    introspectionClient.verify(token, VerifyTelemetry.forRequest(
                        httpReq,
                        resolveScopeUsed(httpReq),
                        VerifyTelemetry.requestDigestFor(body),
                        describeAction(httpReq, body)));

                httpReq.setAttribute("agentadmit.authType", "agent");
                httpReq.setAttribute("agentadmit.userId", result.userId());
                httpReq.setAttribute("agentadmit.scopes", result.scopes());
                httpReq.setAttribute("agentadmit.connectionId", result.connectionId());
                httpReq.setAttribute("agentadmit.agentLabel", result.agentLabel());
                httpReq.setAttribute("agentadmit.presence", result.presence());
                if (result.actionConfirmation() != null) {
                    httpReq.setAttribute("agentadmit.actionConfirmation", result.actionConfirmation());
                }

                logger.debug("AgentAdmit: validated agent token for user={} scopes={}", 
                    result.userId(), result.scopes());

            } catch (AgentAdmitException.ActiveErrorDenial e) {
                // The hosted service refused this call on an active token
                // (e.g. insufficient_scope, bound_exceeded,
                // confirmation_required — whose body carries the staged
                // confirmation link — or an unknown refusal code). Always a
                // 403 denial with the canonical body
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
     * Run the configured {@link ActionSummary} over the request and its cached
     * body. Returns {@code null} when none is configured or the supplier
     * throws — a description is telemetry, and telemetry never blocks a call
     * (the hosted service still refuses a confirm-each-time scope without a
     * confirmation, so nothing is weakened).
     */
    private String describeAction(HttpServletRequest request, byte[] body) {
        ActionSummary summary = options.actionSummary();
        if (summary == null) return null;
        try {
            return summary.describe(request, body == null ? new byte[0] : body);
        } catch (RuntimeException e) {
            logger.debug("AgentAdmit: action summary failed; omitting from telemetry", e);
            return null;
        }
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
