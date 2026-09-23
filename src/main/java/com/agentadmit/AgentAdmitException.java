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
    // ConfirmationRequiredDenial — nested static class
    // -------------------------------------------------------------------------

    /**
     * Confirm-each-time (1.11.0): the refusal {@code confirmation_required}.
     * The token is valid and the scope IS granted, but THIS call needs a fresh
     * human confirmation before it can run.
     *
     * <p>An {@link ActiveErrorDenial}, so every gate that already fails closed
     * on hosted refusals keeps doing so unchanged (403, canonical body, chain
     * not continued). The extra typing is for custom gates that want to relay
     * the ceremony: {@link #getConfirmation()} is the staged
     * {@link ActionConfirmation} (hand {@code actionSessionUrl} to the human;
     * the agent retries with {@code actionSessionId} in the
     * {@value VerifyTelemetry#ACTION_ATTESTATION_HEADER} header) and
     * {@link #getAttestationStatus()} says why an attestation the agent DID
     * present was not accepted ({@code already_consumed}, {@code action_mismatch},
     * {@code expired}, {@code not_confirmed}).
     *
     * <p>A malformed {@code confirmation} block never reaches this type: it is
     * refused as a plain {@link ActiveErrorDenial} with no confirmation block,
     * so a broken ceremony cannot become an allow.
     */
    public static class ConfirmationRequiredDenial extends ActiveErrorDenial {
        /** The hosted ceremony staged for this exact action. */
        private final ActionConfirmation confirmation;
        /** Why a presented attestation was not accepted, or null when none was presented. */
        private final String attestationStatus;

        /**
         * Create a new ConfirmationRequiredDenial. Status is always 403 and
         * the error code is always {@code confirmation_required}.
         *
         * @param message           human-readable refusal description
         * @param responseBody      canonical JSON denial body, carrying the confirmation block
         * @param confirmation      the staged hosted ceremony for this action
         * @param attestationStatus why a presented attestation was rejected, or {@code null}
         */
        public ConfirmationRequiredDenial(String message, String responseBody,
                                          ActionConfirmation confirmation, String attestationStatus) {
            super(message, "confirmation_required", responseBody);
            this.confirmation = confirmation;
            this.attestationStatus = attestationStatus;
        }

        /**
         * Get the staged confirmation ceremony for this exact action.
         * @return the confirmation block (never {@code null} for this type)
         */
        public ActionConfirmation getConfirmation() { return confirmation; }

        /**
         * Get the reason a presented attestation was not accepted.
         * @return e.g. {@code action_mismatch}, or {@code null} when no attestation was presented
         */
        public String getAttestationStatus() { return attestationStatus; }
    }

    // -------------------------------------------------------------------------
    // ConfirmationDeclinedDenial — nested static class
    // -------------------------------------------------------------------------

    /**
     * Confirm-each-time (1.12.0): the refusal {@code confirmation_declined}.
     *
     * <p>The user declined exactly this action on the hosted confirmation
     * page and the hosted service holds that answer until
     * {@code getDeclined().holdUntil()}. No new ceremony is staged and the
     * user is not notified again while the hold runs.
     *
     * <p>An {@link ActiveErrorDenial}, so every gate that already fails closed
     * on hosted refusals keeps doing so unchanged (403, canonical body, chain
     * not continued). The extra typing is for custom gates that want to relay
     * the decline to the user instead of nagging with a link:
     * {@link #getDeclined()} is the typed {@link ActionDecline} and
     * {@link #getAttestationStatus()} says why an attestation the agent DID
     * present was not accepted (e.g. {@code declined}).
     *
     * <p>A malformed {@code declined} block never reaches this type: it is
     * refused as a plain {@link ActiveErrorDenial} with no decline block.
     */
    public static class ConfirmationDeclinedDenial extends ActiveErrorDenial {
        /** The decline the hosted service is holding for this exact action. */
        private final ActionDecline declined;
        /** Why a presented attestation was not accepted, or null when none was presented. */
        private final String attestationStatus;

        /**
         * Create a new ConfirmationDeclinedDenial. Status is always 403 and
         * the error code is always {@code confirmation_declined}.
         *
         * @param message           human-readable refusal description
         * @param responseBody      canonical JSON denial body, carrying the declined block
         * @param declined          the typed decline for this action
         * @param attestationStatus why a presented attestation was rejected, or {@code null}
         */
        public ConfirmationDeclinedDenial(String message, String responseBody,
                                          ActionDecline declined, String attestationStatus) {
            super(message, "confirmation_declined", responseBody);
            this.declined = declined;
            this.attestationStatus = attestationStatus;
        }

        /**
         * Get the decline the hosted service is holding for this exact action.
         * @return the declined block (never {@code null} for this type)
         */
        public ActionDecline getDeclined() { return declined; }

        /**
         * Get the reason a presented attestation was not accepted.
         * @return e.g. {@code declined}, or {@code null} when no attestation was presented
         */
        public String getAttestationStatus() { return attestationStatus; }
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
