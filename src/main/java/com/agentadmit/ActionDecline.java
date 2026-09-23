package com.agentadmit;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Confirm-each-time (1.12.0): the human's explicit no.
 *
 * <p>The user declined exactly this action on the hosted confirmation page,
 * and the hosted service holds that answer until {@link #holdUntil()}. The
 * service answers the agent's retry with {@code active: true} plus
 * {@code error: "confirmation_declined"} and this block; no new ceremony is
 * staged and the user is not notified again while the hold runs. Agents
 * should relay the decline to the user and not retry unless the user asks.
 * Only the user can lift a decline; after the hold ends, a retry stages a
 * fresh confirmation.
 *
 * @param actionSessionId the declined session
 * @param declinedAt      ISO-8601 instant the user declined
 * @param holdUntil       ISO-8601 instant until which no new confirmation can be staged
 * @param scope           the confirm-each-time scope this call exercised
 * @param method          HTTP method the decline is bound to, or {@code null}
 * @param endpoint        request path the decline is bound to, or {@code null}
 * @param requestDigest   {@code sha256:<hex>} of the request body, or {@code null}
 * @param summary         plain-language description the human declined, or {@code null}
 */
public record ActionDecline(
    String actionSessionId,
    String declinedAt,
    String holdUntil,
    String scope,
    String method,
    String endpoint,
    String requestDigest,
    String summary
) {

    /**
     * Strictly typed copy of the wire {@code declined} block: the four
     * identifying fields must each be a JSON string or the whole block is
     * rejected ({@code null}) and the caller falls back to a generic
     * fail-closed refusal with no decline block.
     *
     * @param raw the raw {@code declined} value from the parsed verify response
     * @return the parsed block, or {@code null} when absent or malformed
     */
    static ActionDecline fromVerifyData(Object raw) {
        if (!(raw instanceof Map<?, ?> map)) {
            return null;
        }
        if (!(map.get("action_session_id") instanceof String actionSessionId)
                || !(map.get("declined_at") instanceof String declinedAt)
                || !(map.get("hold_until") instanceof String holdUntil)
                || !(map.get("scope") instanceof String scope)) {
            return null;
        }
        return new ActionDecline(
            actionSessionId,
            declinedAt,
            holdUntil,
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
        wire.put("declined_at", declinedAt);
        wire.put("hold_until", holdUntil);
        wire.put("scope", scope);
        wire.put("method", method);
        wire.put("endpoint", endpoint);
        wire.put("request_digest", requestDigest);
        wire.put("summary", summary);
        return wire;
    }
}
