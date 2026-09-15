package com.agentadmit;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Optional per-call audit telemetry sent with the hosted introspection call.
 *
 * <p>Every field is optional: a field that is unknown at the call site is
 * {@code null} and is omitted from the verify request body — never sent as
 * {@code null} or an empty string. The hosted service stamps the reported
 * values onto the app's tamper-evident audit log; when a field is omitted the
 * audit row honestly records "not reported".
 *
 * <p>Normalization happens at construction, so every instance is already
 * within the hosted contract:
 * <ul>
 *   <li>{@code scopeUsed} — the single declared scope the integration point is
 *       enforcing for THIS call (never a joined list). Blank collapses to
 *       {@code null}; capped at {@value #MAX_SCOPE_USED_LENGTH} characters.</li>
 *   <li>{@code endpoint} — the inbound request path, PATH ONLY: anything from
 *       the first {@code ?} or {@code #} on is stripped (query strings can
 *       carry PII) and the result is truncated to
 *       {@value #MAX_ENDPOINT_LENGTH} characters.</li>
 *   <li>{@code method} — the HTTP method, uppercased and truncated to
 *       {@value #MAX_METHOD_LENGTH} characters.</li>
 *   <li>{@code actionAttestationId} — confirm-each-time (1.11.0): the
 *       single-use id from a completed hosted confirmation ceremony, read off
 *       the agent's {@value #ACTION_ATTESTATION_HEADER} header on its retry.
 *       Trimmed; capped at {@value #MAX_ACTION_ATTESTATION_ID_LENGTH}.</li>
 *   <li>{@code requestDigest} — {@code sha256:<hex>} over the RAW request
 *       body, so a confirmation covers the exact payload, not just the route.
 *       Capped at {@value #MAX_REQUEST_DIGEST_LENGTH}.</li>
 *   <li>{@code actionSummary} — the app's plain-language description of THIS
 *       action, shown to the human on the hosted confirmation page and
 *       committed into the signature. Trimmed; capped at
 *       {@value #MAX_ACTION_SUMMARY_LENGTH}.</li>
 * </ul>
 *
 * @param scopeUsed the single scope being enforced for this call, or {@code null} when unknown
 * @param endpoint  the inbound request path (query string stripped), or {@code null} when unknown
 * @param method    the uppercase HTTP method, or {@code null} when unknown
 * @param consentFirst resolve caller-class consent before hosted scope evaluation
 * @param actionAttestationId the agent's confirm-each-time attestation id, or {@code null}
 * @param requestDigest {@code sha256:} digest of the request body, or {@code null}
 * @param actionSummary the app's description of this action for the human, or {@code null}
 */
public record VerifyTelemetry(
    String scopeUsed,
    String endpoint,
    String method,
    boolean consentFirst,
    String actionAttestationId,
    String requestDigest,
    String actionSummary
) {

    /** Hosted cap on {@code scope_used} length. */
    public static final int MAX_SCOPE_USED_LENGTH = 120;
    /** Hosted cap on {@code endpoint} length. */
    public static final int MAX_ENDPOINT_LENGTH = 500;
    /** Hosted cap on {@code method} length. */
    public static final int MAX_METHOD_LENGTH = 20;
    /** Hosted cap on {@code action_attestation_id} length. */
    public static final int MAX_ACTION_ATTESTATION_ID_LENGTH = 120;
    /** Hosted cap on {@code request_digest} length. */
    public static final int MAX_REQUEST_DIGEST_LENGTH = 128;
    /** Hosted cap on {@code action_summary} length. */
    public static final int MAX_ACTION_SUMMARY_LENGTH = 200;

    /**
     * Request header an agent sets on its retry, after the human completed
     * the hosted confirm-each-time ceremony. Servlet header lookup is
     * case-insensitive, so any casing the agent sends is read.
     */
    public static final String ACTION_ATTESTATION_HEADER = "X-AgentAdmit-Action-Attestation";

    /**
     * Canonical constructor; normalizes every field (blank to {@code null},
     * query-string strip, uppercase method, length caps) so no un-normalized
     * instance can exist.
     *
     * @param scopeUsed the single scope being enforced for this call, or {@code null}
     * @param endpoint  the inbound request path, or {@code null}
     * @param method    the HTTP method, or {@code null}
     */
    public VerifyTelemetry {
        scopeUsed = truncate(blankToNull(scopeUsed), MAX_SCOPE_USED_LENGTH);
        endpoint = truncate(stripQuery(blankToNull(endpoint)), MAX_ENDPOINT_LENGTH);
        method = truncate(upper(blankToNull(method)), MAX_METHOD_LENGTH);
        actionAttestationId = truncate(trimToNull(actionAttestationId), MAX_ACTION_ATTESTATION_ID_LENGTH);
        requestDigest = truncate(trimToNull(requestDigest), MAX_REQUEST_DIGEST_LENGTH);
        actionSummary = truncate(trimToNull(actionSummary), MAX_ACTION_SUMMARY_LENGTH);
    }

    /**
     * Backward-compatible constructor for verification without
     * confirm-each-time fields.
     *
     * @param scopeUsed    the single scope being enforced for this call, or {@code null}
     * @param endpoint     the inbound request path, or {@code null}
     * @param method       the HTTP method, or {@code null}
     * @param consentFirst resolve caller-class consent before scope evaluation
     */
    public VerifyTelemetry(String scopeUsed, String endpoint, String method, boolean consentFirst) {
        this(scopeUsed, endpoint, method, consentFirst, null, null, null);
    }

    /** Backward-compatible constructor for ordinary (non-consent-gated) verification.
     *
     * @param scopeUsed the single scope being enforced for this call, or {@code null}
     * @param endpoint  the inbound request path, or {@code null}
     * @param method    the HTTP method, or {@code null}
     */
    public VerifyTelemetry(String scopeUsed, String endpoint, String method) {
        this(scopeUsed, endpoint, method, false, null, null, null);
    }

    /**
     * Build telemetry from explicit values. Any argument may be {@code null};
     * unknown fields are omitted from the verify body.
     *
     * @param scopeUsed the single scope being enforced for this call, or {@code null}
     * @param endpoint  the inbound request path, or {@code null}
     * @param method    the HTTP method, or {@code null}
     * @return normalized telemetry
     */
    public static VerifyTelemetry of(String scopeUsed, String endpoint, String method) {
        return new VerifyTelemetry(scopeUsed, endpoint, method);
    }

    /**
     * Build telemetry from an inbound servlet request: {@code endpoint} from
     * {@link HttpServletRequest#getRequestURI()} (query string stripped) and
     * {@code method} from {@link HttpServletRequest#getMethod()}.
     *
     * @param request   the inbound request, or {@code null} (all request-derived fields omitted)
     * @param scopeUsed the single scope being enforced for this call, or {@code null} when unknown
     * @return normalized telemetry
     */
    public static VerifyTelemetry forRequest(HttpServletRequest request, String scopeUsed) {
        return forRequest(request, scopeUsed, null, null);
    }

    /**
     * Build telemetry from an inbound servlet request for a confirm-each-time
     * route: everything {@link #forRequest(HttpServletRequest, String)}
     * declares, plus the request-body digest and the app's action summary.
     *
     * <p>The agent's {@value #ACTION_ATTESTATION_HEADER} header is picked up
     * here whenever it is present — with or without a summary — so an agent
     * retrying after a confirmation is always able to spend its attestation.
     *
     * @param request       the inbound request, or {@code null}
     * @param scopeUsed     the single scope being enforced for this call, or {@code null}
     * @param requestDigest {@code sha256:<hex>} of the raw request body, or {@code null}
     * @param actionSummary the app's plain-language description of this action, or {@code null}
     * @return normalized telemetry
     */
    public static VerifyTelemetry forRequest(HttpServletRequest request, String scopeUsed,
                                             String requestDigest, String actionSummary) {
        if (request == null) {
            return new VerifyTelemetry(scopeUsed, null, null, false, null, requestDigest, actionSummary);
        }
        return new VerifyTelemetry(scopeUsed, request.getRequestURI(), request.getMethod(), false,
            actionAttestationId(request), requestDigest, actionSummary);
    }

    /**
     * Request telemetry for a caller-identity gate that must resolve consent
     * before scope. Forwards the agent's confirm-each-time attestation header
     * when present.
     *
     * @param request   the inbound request, or {@code null}
     * @param scopeUsed the single scope being enforced for this call, or {@code null}
     * @return normalized telemetry with {@code consent_first} set
     */
    public static VerifyTelemetry forConsentFirstRequest(HttpServletRequest request, String scopeUsed) {
        if (request == null) {
            return new VerifyTelemetry(scopeUsed, null, null, true);
        }
        return new VerifyTelemetry(scopeUsed, request.getRequestURI(), request.getMethod(), true,
            actionAttestationId(request), null, null);
    }

    /**
     * The agent's {@value #ACTION_ATTESTATION_HEADER} header value: first
     * value, trimmed, capped at {@value #MAX_ACTION_ATTESTATION_ID_LENGTH}.
     *
     * @param request the inbound request, or {@code null}
     * @return the attestation id, or {@code null} when the header is absent or blank
     */
    public static String actionAttestationId(HttpServletRequest request) {
        if (request == null) return null;
        String raw;
        try {
            // Servlet getHeader is case-insensitive and returns the first value.
            raw = request.getHeader(ACTION_ATTESTATION_HEADER);
        } catch (RuntimeException e) {
            return null;
        }
        return truncate(trimToNull(raw), MAX_ACTION_ATTESTATION_ID_LENGTH);
    }

    /**
     * {@code sha256:<hex>} over the RAW request body bytes — the digest the
     * hosted confirmation commits to, so a confirmed action cannot be
     * replayed against a different payload.
     *
     * @param body the raw request body bytes, or {@code null}
     * @return the digest, or {@code null} when the body is null or empty
     */
    public static String requestDigestFor(byte[] body) {
        if (body == null || body.length == 0) return null;
        try {
            byte[] hash = java.security.MessageDigest.getInstance("SHA-256").digest(body);
            StringBuilder hex = new StringBuilder(hash.length * 2);
            for (byte b : hash) {
                hex.append(Character.forDigit((b >> 4) & 0xF, 16));
                hex.append(Character.forDigit(b & 0xF, 16));
            }
            return "sha256:" + hex;
        } catch (java.security.NoSuchAlgorithmException e) {
            // SHA-256 is mandated by the JLS; unreachable on a conformant JRE.
            return null;
        }
    }

    private static String trimToNull(String value) {
        if (value == null) return null;
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private static String blankToNull(String value) {
        return (value == null || value.isBlank()) ? null : value;
    }

    private static String stripQuery(String path) {
        if (path == null) return null;
        int query = path.indexOf('?');
        if (query >= 0) path = path.substring(0, query);
        int fragment = path.indexOf('#');
        if (fragment >= 0) path = path.substring(0, fragment);
        return blankToNull(path);
    }

    private static String upper(String value) {
        return value == null ? null : value.toUpperCase(java.util.Locale.ROOT);
    }

    private static String truncate(String value, int max) {
        if (value == null) return null;
        return value.length() <= max ? value : value.substring(0, max);
    }
}
