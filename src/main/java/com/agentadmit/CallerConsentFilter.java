package com.agentadmit;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * Caller-Identity Consent filter: the "classify caller, then gate the right
 * independent path" recipe as a single servlet filter, so an app owner does
 * not have to hand-roll it.
 *
 * <p>One endpoint serves every caller class. On each request the filter:
 * <ol>
 *   <li>classifies the caller from the STRUCTURE of the credential (a class
 *       the caller cannot self-select), before any consent check;</li>
 *   <li>routes to that class's ISOLATED consent path; no path reads or
 *       inherits another class's preference;</li>
 *   <li>permits or denies, and exposes the resolved context as request
 *       attributes ({@code agentadmit.callerClass}, {@code agentadmit.consent},
 *       plus the standard agent attributes on the external-agent path).</li>
 * </ol>
 *
 * <ul>
 *   <li><b>external_agent</b> — an {@code ag_at_} access token: hosted
 *       introspection returns the external-agent consent verdict inline plus
 *       the granted scopes. Consent is evaluated BEFORE scope (a denied
 *       class must not learn scope state or step-up guidance). A missing or
 *       malformed verdict is resolved through the Consent Ledger, fail
 *       closed — absence is never a grant.</li>
 *   <li><b>in_app_ai</b> — your application's own server-side AI code path:
 *       the Consent Ledger {@code /consent/check} for the in-app-AI class.</li>
 *   <li><b>human_session</b> — your application's own permission model
 *       (sharing, roles, grants). Deferred to your existing authorization by
 *       default; opt in to a stored human-session switch with
 *       {@link Options#gateHuman()}.</li>
 * </ul>
 *
 * <p>The three decisions are independent: granting one never grants another.
 *
 * <p><b>SECURITY:</b> this is a consent gate, not an authenticator. It
 * classifies the caller and enforces the per-class CONSENT decision; it does
 * not by itself authenticate a human session. Register it AFTER your own
 * authentication. On the human_session path it defers to your application's
 * permission model and continues the chain without re-authenticating, so a
 * request carrying no agent token reaches your handler as a human session for
 * your own authorization to judge. The external_agent path is always
 * authenticated (hosted introspection); the in_app_ai path always evaluates
 * the ledger.
 */
public class CallerConsentFilter implements Filter {

    /** Human users reaching data through the app's normal UI. */
    public static final String CALLER_CLASS_HUMAN_SESSION = ConsentClient.CALLER_CLASS_HUMAN_SESSION;
    /** The app's own AI features reading user data. */
    public static final String CALLER_CLASS_IN_APP_AI = ConsentClient.CALLER_CLASS_IN_APP_AI;
    /** Third-party AI agents connected through AgentAdmit. */
    public static final String CALLER_CLASS_EXTERNAL_AGENT = ConsentClient.CALLER_CLASS_EXTERNAL_AGENT;

    private static final Logger logger = LoggerFactory.getLogger(CallerConsentFilter.class);

    /**
     * Filter options. All fields are optional; {@link #defaults()} yields a
     * filter that enforces the external-agent path and defers the human path.
     *
     * @param resolveDataOwnerId resolves your app's identifier for the data
     *        owner whose resource is accessed. Required for the in_app_ai
     *        path, and for human_session when {@code gateHuman} is set. The
     *        external-agent owner comes from the token, so it is not used there.
     * @param classifyNonAgent distinguishes your app's own internal-AI code
     *        path from an ordinary human session, deterministically, from the
     *        STRUCTURE of the credential or request context (for example an
     *        internal service token), never a value the caller can set. Must
     *        return {@code human_session} or {@code in_app_ai}. Defaults to
     *        treating non-agent callers as human sessions.
     * @param requiredScope for the external_agent path, require this scope
     *        (403 {@code insufficient_scope} if not granted).
     * @param scopeGroup optional finer-than-class consent group for the ledger.
     * @param gateHuman also gate the human_session class against a stored
     *        human-session consent switch. Off by default: the human path
     *        belongs to your own permission model.
     */
    public record Options(
        Function<HttpServletRequest, String> resolveDataOwnerId,
        Function<HttpServletRequest, String> classifyNonAgent,
        String requiredScope,
        String scopeGroup,
        boolean gateHuman
    ) {
        /** Options enforcing external agents and deferring the human path. */
        public static Options defaults() {
            return new Options(null, null, null, null, false);
        }
    }

    private final AgentAdmitConfig config;
    private final IntrospectionClient introspectionClient;
    private final ConsentClient consentClient;
    private final Options options;

    /**
     * Construct the filter.
     *
     * @param config              AgentAdmit configuration
     * @param introspectionClient client used to verify agent tokens
     * @param consentClient       client used for token-less consent checks
     * @param options             filter options; see {@link Options}
     */
    public CallerConsentFilter(
            AgentAdmitConfig config,
            IntrospectionClient introspectionClient,
            ConsentClient consentClient,
            Options options) {
        this.config = config;
        this.introspectionClient = introspectionClient;
        this.consentClient = consentClient;
        this.options = options == null ? Options.defaults() : options;
    }

    /**
     * Classify the caller from credential structure, before any consent
     * check. An {@code ag_at_} bearer token is an external agent; anything
     * else is resolved by {@link Options#classifyNonAgent()} (default:
     * human_session). The class is derived, never self-selected by the caller.
     *
     * @param request the incoming request
     * @return one of the CALLER_CLASS_* constants
     */
    public String classifyCaller(HttpServletRequest request) {
        String auth = request.getHeader("Authorization");
        if (auth != null
                && auth.length() > 7
                && auth.substring(0, 7).equalsIgnoreCase("Bearer ")
                && auth.substring(7).startsWith(config.getTokenPrefixAccess())) {
            return CALLER_CLASS_EXTERNAL_AGENT;
        }
        if (options.classifyNonAgent() != null) {
            String cls = options.classifyNonAgent().apply(request);
            if (CALLER_CLASS_IN_APP_AI.equals(cls)) {
                return CALLER_CLASS_IN_APP_AI;
            }
        }
        return CALLER_CLASS_HUMAN_SESSION;
    }

    /** {@inheritDoc} */
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpReq = (HttpServletRequest) request;
        HttpServletResponse httpResp = (HttpServletResponse) response;
        String callerClass = classifyCaller(httpReq);
        httpReq.setAttribute("agentadmit.callerClass", callerClass);

        // ── external_agent: hosted introspection carries the verdict + scopes ──
        if (CALLER_CLASS_EXTERNAL_AGENT.equals(callerClass)) {
            String auth = httpReq.getHeader("Authorization");
            String token = auth.substring(7);

            IntrospectionClient.IntrospectionResult result;
            try {
                result = introspectionClient.verify(token);
            } catch (AgentAdmitException e) {
                writeError(httpResp, e.getStatusCode(),
                    e.getStatusCode() == 401 ? "invalid_token" : "introspection_failed",
                    e.getMessage());
                return;
            }

            // Consent first (Patent FIG. 3: the class consent decision precedes
            // scope evaluation). Checking scope first leaked granted-scope state
            // and step-up guidance to callers whose class the owner had denied.
            // The hosted service omits the verdict when its consent-store read
            // fails (designed degraded mode), so an absent or malformed verdict
            // is resolved through the Consent Ledger — never treated as a grant.
            Map<String, Object> consent = result.consent();
            if (consent == null || !(consent.get("granted") instanceof Boolean)) {
                String owner = result.userId();
                if (owner == null || owner.isEmpty()) {
                    writeError(httpResp, 503, "consent_unavailable",
                        "introspection carried no consent verdict and no resolvable data owner");
                    return;
                }
                try {
                    consent = consentClient.checkConsent(
                        owner, CALLER_CLASS_EXTERNAL_AGENT, options.scopeGroup());
                } catch (Exception e) {
                    // Fail closed: an unreachable or erroring ledger denies, never allows.
                    logger.warn("Consent Ledger unavailable for external_agent fallback: {}", e.getMessage());
                    writeError(httpResp, 503, "consent_unavailable", "Consent check failed");
                    return;
                }
            }
            if (!Boolean.TRUE.equals(consent.get("granted"))) {
                writeError(httpResp, 403, "consent_not_granted",
                    "The data owner has not enabled external agent access.");
                return;
            }

            if (options.requiredScope() != null) {
                List<String> granted = result.scopes() == null ? List.of() : result.scopes();
                if (!granted.contains(options.requiredScope())) {
                    writeError(httpResp, 403, "insufficient_scope",
                        "This action requires '" + options.requiredScope() + "' scope.");
                    return;
                }
            }

            httpReq.setAttribute("agentadmit.authType", "agent");
            httpReq.setAttribute("agentadmit.userId", result.userId());
            httpReq.setAttribute("agentadmit.scopes", result.scopes());
            httpReq.setAttribute("agentadmit.connectionId", result.connectionId());
            httpReq.setAttribute("agentadmit.agentLabel", result.agentLabel());
            httpReq.setAttribute("agentadmit.presence", result.presence());
            httpReq.setAttribute("agentadmit.consent", consent);
            chain.doFilter(request, response);
            return;
        }

        // ── in_app_ai: your own AI code path, gated on the ledger ─────────────
        if (CALLER_CLASS_IN_APP_AI.equals(callerClass)) {
            String owner = resolveOwner(httpReq);
            if (owner == null) {
                writeError(httpResp, 500, "server_error",
                    "resolveDataOwnerId is required for the in_app_ai path");
                return;
            }
            Map<String, Object> verdict;
            try {
                verdict = consentClient.checkConsent(owner, CALLER_CLASS_IN_APP_AI, options.scopeGroup());
            } catch (Exception e) {
                // Fail closed: an unreachable or erroring ledger denies, never allows.
                logger.warn("Consent Ledger unavailable for in_app_ai check: {}", e.getMessage());
                writeError(httpResp, 503, "consent_unavailable", "Consent check failed");
                return;
            }
            if (!Boolean.TRUE.equals(verdict.get("granted"))) {
                writeError(httpResp, 403, "consent_not_granted",
                    "The data owner has not enabled in-app AI analysis.");
                return;
            }
            httpReq.setAttribute("agentadmit.authType", "in_app_ai");
            httpReq.setAttribute("agentadmit.consent", verdict);
            chain.doFilter(request, response);
            return;
        }

        // ── human_session: your own permission model (Branch A) ────────────────
        if (options.gateHuman()) {
            String owner = resolveOwner(httpReq);
            if (owner == null) {
                writeError(httpResp, 500, "server_error",
                    "resolveDataOwnerId is required when gateHuman is set");
                return;
            }
            Map<String, Object> verdict;
            try {
                verdict = consentClient.checkConsent(owner, CALLER_CLASS_HUMAN_SESSION, options.scopeGroup());
            } catch (Exception e) {
                logger.warn("Consent Ledger unavailable for human_session check: {}", e.getMessage());
                writeError(httpResp, 503, "consent_unavailable", "Consent check failed");
                return;
            }
            if (!Boolean.TRUE.equals(verdict.get("granted"))) {
                writeError(httpResp, 403, "consent_not_granted",
                    "The data owner has not enabled this access.");
                return;
            }
            httpReq.setAttribute("agentadmit.authType", "user");
            httpReq.setAttribute("agentadmit.consent", verdict);
            chain.doFilter(request, response);
            return;
        }

        // Default: defer the human path to the app's existing authorization.
        httpReq.setAttribute("agentadmit.authType", "user");
        chain.doFilter(request, response);
    }

    private String resolveOwner(HttpServletRequest request) {
        if (options.resolveDataOwnerId() == null) {
            return null;
        }
        String owner = options.resolveDataOwnerId().apply(request);
        return (owner == null || owner.isEmpty()) ? null : owner;
    }

    private static void writeError(HttpServletResponse response, int status, String error, String description)
            throws IOException {
        response.setStatus(status);
        response.setContentType("application/json");
        response.getWriter().write(
            "{\"error\":\"" + error + "\",\"error_description\":\""
                + description.replace("\"", "\\\"") + "\"}");
    }
}
