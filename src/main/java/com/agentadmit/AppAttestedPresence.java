package com.agentadmit;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * App-attested presence: a ceremony fact your app attests at token issuance.
 *
 * <p>Pass an instance to
 * {@link TokensClient.IssueTokenRequestBuilder#presence(AppAttestedPresence)}
 * AFTER verifying and consuming your app's own fresh, purpose-bound
 * WebAuthn/passkey attestation for the mint. The SDK forwards it to the
 * hosted mint as {@code presence: {verified: true, uv: true, method,
 * verified_at}}; the hosted service stores it method-prefixed
 * {@code app:<method>} — the provenance marker that keeps app-attested facts
 * distinct from hosted-witnessed ceremonies.
 *
 * <p><strong>Honesty ceiling:</strong> this is YOUR attestation, recorded and
 * provenance-marked. It is not witnessed by AgentAdmit and not independently
 * verifiable. Only construct one for a ceremony that verified the user with
 * UV (biometric or PIN user verification); {@code verified}/{@code uv}
 * serialize as literal {@code true} and cannot represent anything else — a
 * ceremony without UV carries no presence fact, so simply do not set one.
 *
 * <p>{@code verifiedAt} carries an explicit offset by type and must be
 * recent: the hosted service enforces a 10-minute freshness window with 60
 * seconds of future clock-skew slack.
 *
 * @param method     your ceremony mechanism, 1-60 lowercase
 *                   alphanumeric/underscore characters (e.g. {@code "my_webauthn"})
 * @param verifiedAt when the ceremony completed
 */
public record AppAttestedPresence(
    String method,
    OffsetDateTime verifiedAt
) {

    private static final Pattern METHOD_PATTERN = Pattern.compile("^[a-z0-9_]+$");
    private static final int METHOD_MAX_LENGTH = 60;

    /**
     * Validate against the hosted contract at construction, where the fix is
     * obvious — a malformed fact would otherwise 400 at the hosted mint.
     */
    public AppAttestedPresence {
        if (method == null || method.isEmpty() || method.length() > METHOD_MAX_LENGTH
            || !METHOD_PATTERN.matcher(method).matches()) {
            throw new IllegalArgumentException(
                "method must be 1-" + METHOD_MAX_LENGTH
                    + " lowercase alphanumeric/underscore characters (e.g. \"my_webauthn\")");
        }
        if (verifiedAt == null) {
            throw new IllegalArgumentException(
                "verifiedAt must be set (the ceremony that authorized this mint just happened)");
        }
    }

    /**
     * Convenience factory from an {@link Instant} (serialized as UTC).
     *
     * @param method     your ceremony mechanism
     * @param verifiedAt when the ceremony completed
     * @return the presence fact
     */
    public static AppAttestedPresence of(String method, Instant verifiedAt) {
        if (verifiedAt == null) {
            throw new IllegalArgumentException(
                "verifiedAt must be set (the ceremony that authorized this mint just happened)");
        }
        return new AppAttestedPresence(method, verifiedAt.atOffset(ZoneOffset.UTC));
    }

    /**
     * The exact JSON object forwarded to the hosted mint — {@code verified}
     * and {@code uv} are literal {@code true}; {@code verified_at} is RFC
     * 3339 with an explicit offset (the hosted contract; offset-less
     * timestamps are rejected with 400).
     *
     * @return the wire map
     */
    Map<String, Object> toWire() {
        Map<String, Object> wire = new LinkedHashMap<>();
        wire.put("verified", true);
        wire.put("uv", true);
        wire.put("method", method);
        wire.put("verified_at", verifiedAt.format(DateTimeFormatter.ISO_OFFSET_DATE_TIME));
        return wire;
    }
}
