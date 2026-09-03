package com.agentadmit;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Confirm-each-time (1.11.0): the hosted confirmation ceremony staged for one
 * exact action.
 *
 * <p>Some actions should never run on a standing grant alone — moving money,
 * publishing on the user's behalf, deleting data. A scope marked
 * {@code confirm_each_time} is granted, but EVERY call that exercises it needs
 * a fresh human confirmation. The hosted service answers such a call with
 * {@code active: true} plus {@code error: "confirmation_required"} and this
 * block; the agent hands {@link #actionSessionUrl()} to the human, who
 * confirms with their passkey on AgentAdmit's page (the agent cannot complete
 * the ceremony), then retries the same request with the header
 * {@value VerifyTelemetry#ACTION_ATTESTATION_HEADER} carrying
 * {@link #actionSessionId()}.
 *
 * <p>The confirmation covers exactly one call: the signature commits to the
 * scope, method, endpoint, request digest, and the summary the human was
 * shown. A retry with a different body, route, or method is refused again with
 * {@code attestation_status: "action_mismatch"}.
 *
 * @param actionSessionId  single-use id the agent presents on its retry
 * @param actionSessionUrl hosted confirmation page for the human
 * @param expiresAt        ISO-8601 expiry of the staged ceremony
 * @param scope            the confirm-each-time scope this call exercises
 * @param method           HTTP method the confirmation is bound to, or {@code null}
 * @param endpoint         request path the confirmation is bound to, or {@code null}
 * @param requestDigest    {@code sha256:<hex>} of the request body, or {@code null}
 * @param summary          plain-language description shown to the human, or {@code null}
 */
public record ActionConfirmation(
    String actionSessionId,
    String actionSessionUrl,
    String expiresAt,
    String scope,
    String method,
    String endpoint,
    String requestDigest,
    String summary
) {

    /**
     * Strictly typed copy of the wire {@code confirmation} block.
     *
     * <p>Strict on the fields an agent must be able to act on: the four
     * identifying fields must each be a JSON string or the whole block is
     * rejected ({@code null}), and the caller falls back to a generic
     * fail-closed refusal with no confirmation block. The four binding fields
     * are nullable by contract, so a missing or mistyped value reads as
     * {@code null} rather than voiding the ceremony.
     *
     * @param raw the raw {@code confirmation} value from the parsed verify response
     * @return the parsed block, or {@code null} when absent or malformed
     */
    static ActionConfirmation fromVerifyData(Object raw) {
        if (!(raw instanceof Map<?, ?> map)) {
            return null;
        }
        if (!(map.get("action_session_id") instanceof String actionSessionId)
                || !(map.get("action_session_url") instanceof String actionSessionUrl)
                || !(map.get("expires_at") instanceof String expiresAt)
                || !(map.get("scope") instanceof String scope)) {
            return null;
        }
        return new ActionConfirmation(
            actionSessionId,
            actionSessionUrl,
            expiresAt,
            scope,
            map.get("method") instanceof String s ? s : null,
            map.get("endpoint") instanceof String s ? s : null,
            map.get("request_digest") instanceof String s ? s : null,
            map.get("summary") instanceof String s ? s : null
        );
    }

    /**
     * The block in its wire (snake_case) shape, for the 403 body the filter
     * relays to the agent. Nullable fields are kept as explicit JSON nulls so
     * the agent sees the full contract, exactly as the other SDKs emit it.
     *
     * @return an ordered map of the wire field names to their values
     */
    Map<String, Object> toWireMap() {
        Map<String, Object> wire = new LinkedHashMap<>();
        wire.put("action_session_id", actionSessionId);
        wire.put("action_session_url", actionSessionUrl);
        wire.put("expires_at", expiresAt);
        wire.put("scope", scope);
        wire.put("method", method);
        wire.put("endpoint", endpoint);
        wire.put("request_digest", requestDigest);
        wire.put("summary", summary);
        return wire;
    }

    /**
     * A confirm-each-time ceremony that was CONSUMED on an accepted verify:
     * this call was allowed because the hosted service spent a human
     * confirmation for exactly this action.
     *
     * <p>Surfaced on {@link IntrospectionClient.IntrospectionResult} and as
     * the {@code agentadmit.actionConfirmation} request attribute, and only
     * ever when the wire block is strictly a string session id together with
     * {@code consumed: true} — anything else is absent. An app that runs its
     * own transaction step-up can treat this as that confirmation instead of
     * asking the human twice.
     *
     * @param actionSessionId the confirmation the hosted service consumed for this call
     */
    public record Consumed(String actionSessionId) {

        /**
         * Always {@code true}: an instance exists only for a consumed
         * confirmation.
         *
         * @return {@code true}
         */
        public boolean consumed() {
            return true;
        }

        /**
         * Parse the {@code action_confirmation} block off an accepted verify
         * response. Strict, like {@code active}: only a block whose
         * {@code action_session_id} is a String and whose {@code consumed} is
         * {@code Boolean.TRUE} is surfaced; absent, mistyped, or
         * not-yet-consumed blocks yield {@code null}.
         *
         * @param raw the raw {@code action_confirmation} value from the verify response
         * @return the consumed confirmation, or {@code null} when absent or malformed
         */
        static Consumed fromVerifyData(Object raw) {
            if (!(raw instanceof Map<?, ?> map)) {
                return null;
            }
            if (!(map.get("action_session_id") instanceof String actionSessionId)) {
                return null;
            }
            if (!Boolean.TRUE.equals(map.get("consumed"))) {
                return null;
            }
            return new Consumed(actionSessionId);
        }
    }
}
