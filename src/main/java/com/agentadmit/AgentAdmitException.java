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
