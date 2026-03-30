package app.agentadmit;

/**
 * Exception thrown by AgentAdmit SDK operations.
 */
public class AgentAdmitException extends RuntimeException {
    private final int statusCode;

    public AgentAdmitException(String message, int statusCode) {
        super(message);
        this.statusCode = statusCode;
    }

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

        public RateLimitError(String message, double retryAfter, int limit, int remaining, long reset) {
            super(message, 429);
            this.retryAfter = retryAfter;
            this.limit = limit;
            this.remaining = remaining;
            this.reset = reset;
        }

        /** @return Retry-After seconds, or -1 if header was absent. */
        public double getRetryAfter() { return retryAfter; }

        /** @return X-RateLimit-Limit, or -1 if header was absent. */
        public int getLimit() { return limit; }

        /** @return X-RateLimit-Remaining, or -1 if header was absent. */
        public int getRemaining() { return remaining; }

        /** @return X-RateLimit-Reset (Unix timestamp), or -1 if header was absent. */
        public long getReset() { return reset; }
    }
}
