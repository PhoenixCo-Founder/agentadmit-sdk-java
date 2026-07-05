package com.agentadmit;

import java.util.Map;

/**
 * Human-presence fact from the WebAuthn step-up: whether the human who
 * authorized the connection completed a presence ceremony on the consent
 * page. Additive; older servers omit the block entirely, and connections
 * minted without a ceremony (direct-API tokens, presence-off sessions,
 * pre-presence connections) arrive with {@code verified: false}.
 *
 * <p>All fields are boxed so an unverified block can carry {@code null}
 * for the ceremony details.
 *
 * @param verified   whether a presence ceremony was completed for the connection
 * @param method     ceremony type, e.g. {@code "webauthn"}; {@code null} when never verified
 * @param uv         authenticator user-verification flag reported by the ceremony;
 *                   {@code null} when never verified
 * @param verifiedAt ISO-8601 timestamp of the ceremony; {@code null} when never verified
 */
public record Presence(
    Boolean verified,
    String method,
    Boolean uv,
    String verifiedAt
) {

    /**
     * Parse the {@code presence} block out of a verify response.
     *
     * <p>Strictness mirrors how {@code active} is checked: {@code verified}
     * must be strictly a JSON boolean. A block that is absent, not an object,
     * or whose {@code verified} field is missing or mistyped yields
     * {@code null}, exactly like a legacy server that never sent it.
     * Mistyped optional fields ({@code method}, {@code uv},
     * {@code verified_at}) are tolerated as {@code null}.
     *
     * @param raw the raw {@code presence} value from the parsed verify response
     * @return the parsed block, or {@code null} when absent or malformed
     */
    static Presence fromVerifyData(Object raw) {
        if (!(raw instanceof Map<?, ?> map)) {
            return null;
        }
        if (!(map.get("verified") instanceof Boolean verifiedFlag)) {
            return null;
        }
        String method = map.get("method") instanceof String s ? s : null;
        Boolean uv = map.get("uv") instanceof Boolean b ? b : null;
        String verifiedAt = map.get("verified_at") instanceof String s ? s : null;
        return new Presence(verifiedFlag, method, uv, verifiedAt);
    }

    /**
     * Whether the ceremony was completed. Strict: only {@code Boolean.TRUE}
     * counts (fail closed).
     *
     * @return {@code true} only when {@code verified} is {@code Boolean.TRUE}
     */
    public boolean isVerified() {
        return Boolean.TRUE.equals(verified);
    }
}
