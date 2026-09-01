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
 * </ul>
 *
 * @param scopeUsed the single scope being enforced for this call, or {@code null} when unknown
 * @param endpoint  the inbound request path (query string stripped), or {@code null} when unknown
 * @param method    the uppercase HTTP method, or {@code null} when unknown
 */
public record VerifyTelemetry(String scopeUsed, String endpoint, String method, boolean consentFirst) {

    /** Hosted cap on {@code scope_used} length. */
    public static final int MAX_SCOPE_USED_LENGTH = 120;
    /** Hosted cap on {@code endpoint} length. */
    public static final int MAX_ENDPOINT_LENGTH = 500;
    /** Hosted cap on {@code method} length. */
    public static final int MAX_METHOD_LENGTH = 20;

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
    }

    /** Backward-compatible constructor for ordinary (non-consent-gated) verification. */
    public VerifyTelemetry(String scopeUsed, String endpoint, String method) {
        this(scopeUsed, endpoint, method, false);
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
        if (request == null) {
            return new VerifyTelemetry(scopeUsed, null, null);
        }
        return new VerifyTelemetry(scopeUsed, request.getRequestURI(), request.getMethod());
    }

    /** Request telemetry for a caller-identity gate that must resolve consent before scope. */
    public static VerifyTelemetry forConsentFirstRequest(HttpServletRequest request, String scopeUsed) {
        if (request == null) {
            return new VerifyTelemetry(scopeUsed, null, null, true);
        }
        return new VerifyTelemetry(scopeUsed, request.getRequestURI(), request.getMethod(), true);
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
