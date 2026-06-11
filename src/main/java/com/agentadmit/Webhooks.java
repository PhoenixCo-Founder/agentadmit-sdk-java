package com.agentadmit;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

/**
 * Verification for inbound AgentAdmit alert webhooks.
 *
 * <p>AgentAdmit signs every alert webhook delivery with the app's webhook
 * signing secret ({@code whsec_…}, returned once when the webhook URL is
 * configured). The signature arrives in the {@code X-AgentAdmit-Signature}
 * header:
 *
 * <pre>X-AgentAdmit-Signature: t=&lt;unix_ts&gt;,v1=&lt;hex hmac-sha256&gt;</pre>
 *
 * <p>where the HMAC input is {@code "{t}.{rawBody}"} keyed with the full
 * whsec_ secret. Always verify against the raw request body bytes, before
 * any JSON parsing.
 *
 * <pre>{@code
 * @PostMapping("/agentadmit/alerts")
 * public ResponseEntity<Void> alerts(@RequestBody byte[] payload,
 *                                    @RequestHeader("X-AgentAdmit-Signature") String signature) {
 *     try {
 *         Webhooks.verifySignature(payload, signature, webhookSecret);
 *     } catch (AgentAdmitException e) {
 *         return ResponseEntity.badRequest().build();
 *     }
 *     // payload is authentic — parse and handle the alert
 *     return ResponseEntity.ok().build();
 * }
 * }</pre>
 */
public final class Webhooks {

    /** Header AgentAdmit signs alert webhook deliveries with. */
    public static final String SIGNATURE_HEADER = "X-AgentAdmit-Signature";

    /** Default maximum clock skew (seconds) allowed for replay protection. */
    public static final long DEFAULT_TOLERANCE_SECONDS = 300;

    private Webhooks() {}

    /**
     * Verify the X-AgentAdmit-Signature header on an inbound alert webhook
     * using the default 300-second replay tolerance.
     *
     * @param payload the raw request body bytes
     * @param signatureHeader the X-AgentAdmit-Signature header value
     * @param secret the app's webhook signing secret (whsec_…)
     * @throws AgentAdmitException if the header is missing/malformed, the
     *         timestamp is outside the tolerance window, or no signature
     *         matches; the message never includes the secret or payload
     */
    public static void verifySignature(byte[] payload, String signatureHeader, String secret)
            throws AgentAdmitException {
        verifySignature(payload, signatureHeader, secret, DEFAULT_TOLERANCE_SECONDS,
            System.currentTimeMillis() / 1000);
    }

    /**
     * Verify with a custom replay tolerance. Pass 0 to disable the timestamp
     * check.
     *
     * @param payload the raw request body bytes
     * @param signatureHeader the X-AgentAdmit-Signature header value
     * @param secret the app's webhook signing secret (whsec_…)
     * @param toleranceSeconds maximum allowed clock skew in seconds
     * @throws AgentAdmitException on any verification failure
     */
    public static void verifySignature(byte[] payload, String signatureHeader, String secret,
                                       long toleranceSeconds) throws AgentAdmitException {
        verifySignature(payload, signatureHeader, secret, toleranceSeconds,
            System.currentTimeMillis() / 1000);
    }

    // Package-private overload with injectable clock, for tests.
    static void verifySignature(byte[] payload, String signatureHeader, String secret,
                                long toleranceSeconds, long nowEpochSeconds)
            throws AgentAdmitException {
        if (secret == null || secret.isEmpty()) {
            throw new AgentAdmitException("Webhook signing secret is required", 400);
        }
        if (signatureHeader == null || signatureHeader.isEmpty()) {
            throw new AgentAdmitException("Missing X-AgentAdmit-Signature header", 400);
        }

        long timestamp = -1;
        List<String> candidates = new ArrayList<>();
        for (String part : signatureHeader.split(",")) {
            int eq = part.indexOf('=');
            if (eq < 0) continue;
            String key = part.substring(0, eq).trim();
            String value = part.substring(eq + 1).trim();
            if (key.equals("t")) {
                try {
                    timestamp = Long.parseLong(value);
                } catch (NumberFormatException e) {
                    throw new AgentAdmitException("Malformed signature header", 400);
                }
            } else if (key.equals("v1")) {
                candidates.add(value);
            }
        }

        if (timestamp < 0 || candidates.isEmpty()) {
            throw new AgentAdmitException("Malformed signature header", 400);
        }

        if (toleranceSeconds > 0 && Math.abs(nowEpochSeconds - timestamp) > toleranceSeconds) {
            throw new AgentAdmitException("Signature timestamp outside tolerance window", 400);
        }

        byte[] expected = hexHmacSha256(secret, timestamp + ".", payload)
            .getBytes(StandardCharsets.UTF_8);
        for (String candidate : candidates) {
            if (MessageDigest.isEqual(expected, candidate.getBytes(StandardCharsets.UTF_8))) {
                return;
            }
        }
        throw new AgentAdmitException("Webhook signature verification failed", 400);
    }

    /**
     * Boolean form of {@link #verifySignature(byte[], String, String)}.
     *
     * @param payload the raw request body bytes
     * @param signatureHeader the X-AgentAdmit-Signature header value
     * @param secret the app's webhook signing secret (whsec_…)
     * @return {@code true} if the signature is valid and fresh
     */
    public static boolean isValidSignature(byte[] payload, String signatureHeader, String secret) {
        try {
            verifySignature(payload, signatureHeader, secret);
            return true;
        } catch (AgentAdmitException e) {
            return false;
        }
    }

    private static String hexHmacSha256(String secret, String prefix, byte[] payload)
            throws AgentAdmitException {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            mac.update(prefix.getBytes(StandardCharsets.UTF_8));
            byte[] digest = mac.doFinal(payload);
            StringBuilder hex = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                hex.append(Character.forDigit((b >> 4) & 0xF, 16));
                hex.append(Character.forDigit(b & 0xF, 16));
            }
            return hex.toString();
        } catch (Exception e) {
            throw new AgentAdmitException("HMAC computation failed", 500);
        }
    }
}
