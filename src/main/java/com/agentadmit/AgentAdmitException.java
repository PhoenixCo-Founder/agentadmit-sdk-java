package com.agentadmit;

/**
 * Exception thrown by AgentAdmit SDK operations.
 */
public class AgentAdmitException extends RuntimeException {

    /** HTTP status code associated with this error (e.g. 401, 403, 429, 502). */
    private final int statusCode;

    /**
     * Create a new AgentAdmitException.
     *
     * @param message    human-readable error description
     * @param statusCode HTTP status code to surface in the response
     */
    public AgentAdmitException(String message, int statusCode) {
        super(message);
        this.statusCode = statusCode;
    }

    /**
     * Returns the HTTP status code associated with this error.
     *
     * @return HTTP status code (e.g. 401, 403, 429, 502)
     */
    public int getStatusCode() { return statusCode; }

    // -------------------------------------------------------------------------
    // ActiveErrorDenial — nested static class
    // -------------------------------------------------------------------------

    /**
     * Thrown when the hosted introspection response reports {@code active: true}
     * together with a string {@code error} field. Such a response is a REFUSAL
     * of this specific call (the token itself stays valid), never a
     * pass-through — for example {@code insufficient_scope} (the requested
     * scope is not granted) or {@code bound_exceeded} (a bounded capability is
     * exhausted). Unknown error codes are refused the same way, fail closed.
     *
     * <p>Always carries HTTP status 403 and a ready-to-write JSON response
     * body in the canonical denial shape for the error code, so filters and
     * handlers can relay the refusal without rebuilding it:
     * <ul>
     *   <li>{@code insufficient_scope} — {@code {error, required_scope,
     *       granted_scopes}} (the step-up shape, matching the local scope
     *       check in {@link ScopeEnforcementAspect}).</li>
     *   <li>{@code bound_exceeded} — {@code {error, error_description,
     *       bound?, renewal?}} with the hosted fields passed through
     *       verbatim.</li>
     *   <li>any other code — {@code {error, error_description}} with a
     *       generic refusal description.</li>
     * </ul>
     */
    public static class ActiveErrorDenial extends AgentAdmitException {
        /** The error code reported by the hosted service (e.g. {@code bound_exceeded}). */
        private final String errorCode;
        /** Canonical JSON denial body for this error code, ready to write. */
        private final String responseBody;

        /**
         * Create a new ActiveErrorDenial. Status is always 403.
         *
         * @param message      human-readable refusal description
         * @param errorCode    the error code reported by the hosted service
         * @param responseBody canonical JSON denial body for this error code
         */
        public ActiveErrorDenial(String message, String errorCode, String responseBody) {
            super(message, 403);
            this.errorCode = errorCode;
            this.responseBody = responseBody;
        }

        /**
         * Get the error code reported by the hosted service.
         * @return the error code (e.g. {@code insufficient_scope}, {@code bound_exceeded})
         */
        public String getErrorCode() { return errorCode; }

        /**
         * Get the canonical JSON denial body for this refusal.
         * @return a ready-to-write JSON response body
         */
        public String getResponseBody() { return responseBody; }
    }

    // -------------------------------------------------------------------------
    // RateLimitError — nested static class
    // -------------------------------------------------------------------------

    /**
     * Thrown when the AgentAdmit introspection endpoint returns HTTP 429 and
     * all retry attempts (with exponential backoff + jitter) are exhausted.
     *
     * <p>Inspect {@link #getRetryAfter()}, {@link #getLimit()},
     * {@link #getRemaining()}, and {@link #getReset()} to surface rate-limit
     * details in your API response.
     *
     * <pre>{@code
     * try {
     *     client.verify(token);
     * } catch (AgentAdmitException.RateLimitError e) {
     *     response.setStatus(429);
     *     // e.getRetryAfter(), e.getLimit(), ...
     * }
     * }</pre>
     */
    public static class RateLimitError extends AgentAdmitException {
        /** Seconds to wait before retrying (Retry-After header), or -1 if absent. */
        private final double retryAfter;
        /** X-RateLimit-Limit value, or -1 if absent. */
        private final int limit;
        /** X-RateLimit-Remaining value, or -1 if absent. */
        private final int remaining;
        /** X-RateLimit-Reset value (Unix timestamp), or -1 if absent. */
        private final long reset;

        /**
         * Create a new RateLimitError with rate-limit header values.
         *
         * @param message    human-readable error description
         * @param retryAfter Retry-After seconds, or -1 if absent
         * @param limit      X-RateLimit-Limit, or -1 if absent
         * @param remaining  X-RateLimit-Remaining, or -1 if absent
         * @param reset      X-RateLimit-Reset Unix timestamp, or -1 if absent
         */
        public RateLimitError(String message, double retryAfter, int limit, int remaining, long reset) {
            super(message, 429);
            this.retryAfter = retryAfter;
            this.limit = limit;
            this.remaining = remaining;
            this.reset = reset;
        }

        /**
         * Get the Retry-After value in seconds.
         * @return seconds to wait, or -1 if header was absent
         */
        public double getRetryAfter() { return retryAfter; }

        /**
         * Get the rate limit ceiling.
         * @return X-RateLimit-Limit, or -1 if header was absent
         */
        public int getLimit() { return limit; }

        /**
         * Get the remaining requests in the current window.
         * @return X-RateLimit-Remaining, or -1 if absent
         */
        public int getRemaining() { return remaining; }

        /**
         * Get the Unix timestamp when the rate limit resets.
         * @return X-RateLimit-Reset timestamp, or -1 if absent
         */
        public long getReset() { return reset; }
    }
}
