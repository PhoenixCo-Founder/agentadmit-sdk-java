package com.agentadmit;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Mandatory introspection client — validates tokens via AgentAdmit hosted service.
 * No local JWT decode. Every verification call goes through AgentAdmit.
 */
@Component
public class IntrospectionClient {

    private static final Logger logger = LoggerFactory.getLogger(IntrospectionClient.class);

    /** Hard cap (ms) on any single retry wait — including a server-supplied Retry-After. */
    static final long MAX_RETRY_WAIT_MS = 30_000L;

    /** Hard cap (ms) on cumulative wait across all retries of a single verify call. */
    static final long MAX_RETRY_BUDGET_MS = 120_000L;

    private final AgentAdmitConfig config;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;

    /**
     * Construct the introspection client.
     *
     * @param config AgentAdmit configuration providing API key and endpoint URLs
     */
    public IntrospectionClient(AgentAdmitConfig config) {
        this.config = config;
        this.httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();
        this.objectMapper = new ObjectMapper();
    }

    /**
     * Validate an ag_at_ token via introspection.
     *
     * <p>Automatically retries on HTTP 429 with exponential backoff + jitter.
     * Throws {@link AgentAdmitException.RateLimitError} when retries are exhausted.
     *
     * @param token The full token including ag_at_ prefix
     * @return IntrospectionResult with scopes, user_id, connection_id
     * @throws AgentAdmitException if validation fails
     * @throws AgentAdmitException.RateLimitError if rate-limited and retries exhausted
     */
    public IntrospectionResult verify(String token) throws AgentAdmitException {
        if (!token.startsWith(config.getTokenPrefixAccess())) {
            throw new AgentAdmitException("Not an AgentAdmit access token", 401);
        }

        int maxRetries = config.getMaxRetries();
        long delayMs = 1_000L;  // initial backoff: 1 second
        long waitedMs = 0L;     // cumulative wait across retries

        for (int attempt = 0; attempt <= maxRetries; attempt++) {
            HttpResponse<String> response = sendIntrospectionRequest(token);

            int status = response.statusCode();

            if (status == 429) {
                // Parse rate-limit headers
                double retryAfter  = parseDoubleHeader(response, "Retry-After");
                int    rlLimit     = parseIntHeader(response,    "X-RateLimit-Limit");
                int    rlRemaining = parseIntHeader(response,    "X-RateLimit-Remaining");
                long   rlReset     = parseLongHeader(response,   "X-RateLimit-Reset");

                if (attempt >= maxRetries) {
                    throw new AgentAdmitException.RateLimitError(
                        "AgentAdmit rate limit exceeded. Max retries (" + maxRetries + ") exhausted.",
                        retryAfter, rlLimit, rlRemaining, rlReset
                    );
                }

                // Compute wait: Retry-After beats exponential backoff, but both
                // are capped — Retry-After is untrusted server input and must
                // not pin the caller.
                long requestedMs = retryAfter >= 0 ? (long)(retryAfter * 1000) : delayMs;
                long waitMs = Math.min(Math.max(0L, requestedMs), MAX_RETRY_WAIT_MS);
                long jitterMs = ThreadLocalRandom.current().nextLong(0, 500);
                long totalWaitMs = waitMs + jitterMs;

                if (waitedMs + totalWaitMs > MAX_RETRY_BUDGET_MS) {
                    throw new AgentAdmitException.RateLimitError(
                        "AgentAdmit rate limit retry budget (" + (MAX_RETRY_BUDGET_MS / 1000) + "s) exhausted.",
                        retryAfter, rlLimit, rlRemaining, rlReset
                    );
                }
                waitedMs += totalWaitMs;

                logger.warn("AgentAdmit introspection rate-limited (attempt {}/{}). Retrying in {}ms.",
                    attempt + 1, maxRetries, totalWaitMs);

                sleepBeforeRetry(totalWaitMs);

                delayMs = Math.min(delayMs * 2, 30_000L);
                continue;
            }

            // Non-429 response — process normally
            try {
                if (status == 401) {
                    Map<String, Object> errData = objectMapper.readValue(response.body(), Map.class);
                    String desc = (String) errData.getOrDefault("error_description", "Token validation failed");
                    throw new AgentAdmitException(desc, 401);
                }

                if (status < 200 || status > 299) {
                    throw new AgentAdmitException("Verification service returned " + status, 502);
                }

                Map<String, Object> data = objectMapper.readValue(response.body(), Map.class);

                // Check active flag (RFC 7662 introspection pattern).
                // active must be strictly Boolean true — null, false, or a
                // non-boolean value all mean the token is invalid/expired/revoked.
                Object activeRaw = data.get("active");
                if (!Boolean.TRUE.equals(activeRaw)) {
                    String reason = (data.get("error") instanceof String s) ? s : "invalid_token";
                    throw new AgentAdmitException("Token is not active: " + reason, 401);
                }

                // insufficient_scope arrives with active: true (token valid,
                // requested scope not granted) — treat it as a 403.
                if ("insufficient_scope".equals(data.get("error"))) {
                    String desc = (String) data.getOrDefault("error_description", "Scope not granted");
                    throw new AgentAdmitException(desc, 403);
                }

                // Validate that string fields are actually strings when present
                // (not numbers, booleans, or objects), and that scopes is a list
                // of strings. A well-formed response from the hosted service will
                // always satisfy these; mismatches indicate a spoofed or
                // malformed response that must be rejected.
                String userId = requireStringField(data, "user_id");
                String agentId = requireStringFieldIfPresent(data, "agent_id");
                String connectionId = requireStringFieldIfPresent(data, "connection_id");
                List<String> scopes = requireStringList(data, "scopes");
                String agentLabel = (String) data.getOrDefault("agent_label", "Unknown Agent");
                String sub = requireStringFieldIfPresent(data, "sub");
                String role = requireStringFieldIfPresent(data, "role");
                String appId = requireStringFieldIfPresent(data, "app_id");
                String jti = requireStringFieldIfPresent(data, "jti");
                // Declared purpose: the user-facing reason recorded on the
                // grant at the consent moment. Review-time record only, never
                // an enforcement input — so it follows the presence-block
                // tolerance convention for metadata, not the identity-field
                // strictness: absent or malformed reads as null.
                String purpose = data.get("purpose") instanceof String ps ? ps : null;
                // User-declared intent: the user's own words, typed at the
                // consent moment (distinct from purpose, the app's words).
                // Review-time record only, never an enforcement input — same
                // metadata tolerance as purpose: absent or malformed reads
                // as null, never a rejection.
                String userIntent = data.get("user_intent") instanceof String uis ? uis : null;
                long exp = data.get("exp") instanceof Number n ? n.longValue() : 0L;

                if (userId == null) {
                    throw new AgentAdmitException("Introspection returned no user", 401);
                }

                // Keep the consent map whenever it is present, even if its
                // "granted" field is missing or mistyped. consentGranted()
                // fails closed on absent AND malformed verdicts — the hosted
                // service omits the block when its consent-store read fails
                // (degraded mode), so absence is never a grant. Consumers
                // that need a verdict resolve absence through the Consent
                // Ledger, as CallerConsentFilter does.
                Map<String, Object> consent = null;
                if (data.get("consent") instanceof Map<?, ?> consentMap) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> cast = (Map<String, Object>) consentMap;
                    consent = cast;
                }

                // Human-presence fact rides along when the platform returns
                // it. Same strictness as active: verified must be strictly
                // boolean, never coerced. Absent or malformed blocks leave
                // presence null (older servers omit it entirely);
                // isPresenceVerified() then reports false (fail closed).
                Presence presence = Presence.fromVerifyData(data.get("presence"));

                return new IntrospectionResult(userId, connectionId, scopes, agentLabel, sub, role, appId, jti, exp, consent, presence, purpose, userIntent);
            } catch (AgentAdmitException e) {
                throw e;
            } catch (Exception e) {
                logger.error("AgentAdmit introspection failed: {}", e.getMessage());
                throw new AgentAdmitException("Introspection failed: " + e.getMessage(), 502);
            }
        }

        // Should never be reached
        throw new AgentAdmitException("Unexpected exit from retry loop", 500);
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /** Sleep before the next retry. Package-visible so tests can record instead of sleeping. */
    void sleepBeforeRetry(long totalWaitMs) throws AgentAdmitException {
        try {
            Thread.sleep(totalWaitMs);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            throw new AgentAdmitException("Interrupted while retrying after rate limit", 429);
        }
    }

    /** Package-visible so tests can stub the hosted-service response. */
    HttpResponse<String> sendIntrospectionRequest(String token) throws AgentAdmitException {
        try {
            // Serialize via Jackson — string concatenation would allow JSON
            // injection through a hostile token value.
            String body = objectMapper.writeValueAsString(Map.of("token", token));
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(config.getVerifyUrl()))
                .header("Authorization", "Bearer " + config.getApiKey())
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .timeout(Duration.ofSeconds(5))
                .build();
            return httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (Exception e) {
            logger.error("AgentAdmit introspection network error: {}", e.getMessage());
            throw new AgentAdmitException("Introspection failed: " + e.getMessage(), 502);
        }
    }

    /**
     * Require that {@code field} is a String value, or null if absent.
     * Returns the String value, or null if the field is absent.
     * Throws if the field is present but not a String.
     */
    private String requireStringField(Map<String, Object> data, String field) throws AgentAdmitException {
        Object val = data.get(field);
        if (val == null) return null;
        if (!(val instanceof String)) {
            throw new AgentAdmitException(
                "Introspection response field '" + field + "' must be a string, got: "
                + val.getClass().getSimpleName(), 401);
        }
        return (String) val;
    }

    /**
     * Same as {@link #requireStringField} but does not require the field to be present.
     * Equivalent to requireStringField — both return null when absent, both throw when
     * present-but-wrong-type.
     */
    private String requireStringFieldIfPresent(Map<String, Object> data, String field)
            throws AgentAdmitException {
        return requireStringField(data, field);
    }

    /**
     * Require that {@code scopes} field is a list of strings, or absent (defaults to empty list).
     * Throws if the field is present but is not a list, or contains non-string elements.
     */
    @SuppressWarnings("unchecked")
    private List<String> requireStringList(Map<String, Object> data, String field)
            throws AgentAdmitException {
        Object val = data.get(field);
        if (val == null) return List.of();
        if (!(val instanceof List)) {
            throw new AgentAdmitException(
                "Introspection response field '" + field + "' must be a list of strings, got: "
                + val.getClass().getSimpleName(), 401);
        }
        List<?> list = (List<?>) val;
        for (Object item : list) {
            if (!(item instanceof String)) {
                throw new AgentAdmitException(
                    "Introspection response field '" + field + "' must contain only strings, got element: "
                    + (item == null ? "null" : item.getClass().getSimpleName()), 401);
            }
        }
        return (List<String>) list;
    }

    /** Returns the header value as a double, or -1 if absent/invalid. */
    private double parseDoubleHeader(HttpResponse<?> response, String name) {
        return response.headers().firstValue(name).map(v -> {
            try { return Double.parseDouble(v); } catch (NumberFormatException e) { return -1.0; }
        }).orElse(-1.0);
    }

    /** Returns the header value as an int, or -1 if absent/invalid. */
    private int parseIntHeader(HttpResponse<?> response, String name) {
        return response.headers().firstValue(name).map(v -> {
            try { return Integer.parseInt(v); } catch (NumberFormatException e) { return -1; }
        }).orElse(-1);
    }

    /** Returns the header value as a long, or -1 if absent/invalid. */
    private long parseLongHeader(HttpResponse<?> response, String name) {
        return response.headers().firstValue(name).map(v -> {
            try { return Long.parseLong(v); } catch (NumberFormatException e) { return -1L; }
        }).orElse(-1L);
    }

    /**
     * Result of a successful introspection call.
     *
     * @param userId       the end user's identifier
     * @param connectionId the AgentAdmit connection identifier
     * @param scopes       list of granted scope strings
     * @param agentLabel   human-readable agent display name
     * @param sub          token subject
     * @param role         the user's role granted on the connection
     * @param appId        the AgentAdmit application identifier
     * @param jti          unique JWT ID of the access token
     * @param exp          token expiry as a Unix timestamp (0 if absent)
     * @param consent      Consent Ledger verdict for the external-agent path (null if absent)
     * @param presence     human-presence fact for the connection (null if absent or malformed)
     * @param purpose      declared purpose: the user-facing reason recorded on the
     *                     grant at the consent moment (null if absent). Review-time
     *                     record only, never an enforcement input; authorization
     *                     decisions ride scopes, connection status, and consent.
     * @param userIntent   user-declared intent: the user's own words, typed at the
     *                     consent moment (null if absent; distinct from purpose,
     *                     the app's words). Review-time record only, never an
     *                     enforcement input; authorization decisions ride scopes,
     *                     connection status, and consent.
     */
    public record IntrospectionResult(
        String userId,
        String connectionId,
        List<String> scopes,
        String agentLabel,
        String sub,
        String role,
        String appId,
        String jti,
        long exp,
        Map<String, Object> consent,
        Presence presence,
        String purpose,
        String userIntent
    ) {
        /**
         * Check whether a specific scope was granted.
         *
         * @param scope the scope string to check
         * @return {@code true} if the scope is present in the granted scopes
         */
        public boolean hasScope(String scope) {
            return scopes.contains(scope);
        }

        /**
         * Consent Ledger verdict for the external-agent path (additive; may
         * be {@code null}). Fail closed: only a verdict whose {@code granted}
         * field is exactly {@code Boolean.TRUE} grants. An absent consent map
         * is NEVER a grant — the hosted service deliberately omits the block
         * when its consent-store read fails (degraded mode), so absence must
         * be resolved through the Consent Ledger
         * ({@link ConsentClient#checkConsent}), as {@link CallerConsentFilter}
         * does, or denied. A verdict that is present but whose
         * {@code granted} field is missing or not a boolean is likewise
         * denied. A denied verdict means the app returns its own 403; the
         * token itself stays valid (consent is orthogonal to revocation).
         *
         * @return {@code true} only when {@code consent} is non-null and its
         *         {@code granted} field is {@code Boolean.TRUE}
         */
        public boolean consentGranted() {
            return consent != null && Boolean.TRUE.equals(consent.get("granted"));
        }

        /**
         * Whether the connection behind this token was authorized by a human
         * who completed a presence ceremony (WebAuthn) on the consent page.
         *
         * <p>Strict, matching the fail-closed posture of
         * {@link #consentGranted()}: absent presence data is NOT verified.
         * Only a well-formed block whose {@code verified} field is
         * {@code Boolean.TRUE} counts, so connections from servers that
         * predate the presence feature report {@code false} (fail closed).
         *
         * @return {@code true} only when {@code presence} is non-null and
         *         its {@code verified} field is {@code Boolean.TRUE}
         */
        public boolean isPresenceVerified() {
            return presence != null && Boolean.TRUE.equals(presence.verified());
        }
    }
}
