package com.agentadmit;

import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class WebhooksTest {

    private static final String SECRET = "whsec_test123";
    private static final byte[] PAYLOAD =
        "{\"event\":\"agentadmit.alert\",\"alert_type\":\"usage_spike\"}".getBytes(StandardCharsets.UTF_8);
    private static final long NOW = 1750000000L;

    private static String sign(byte[] payload, String secret, long ts) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        mac.update((ts + ".").getBytes(StandardCharsets.UTF_8));
        return "t=" + ts + ",v1=" + HexFormat.of().formatHex(mac.doFinal(payload));
    }

    @Test
    void validSignaturePasses() throws Exception {
        String header = sign(PAYLOAD, SECRET, NOW);
        assertDoesNotThrow(() ->
            Webhooks.verifySignature(PAYLOAD, header, SECRET, Webhooks.DEFAULT_TOLERANCE_SECONDS, NOW));
    }

    @Test
    void tamperedPayloadFails() throws Exception {
        String header = sign(PAYLOAD, SECRET, NOW);
        byte[] tampered = (new String(PAYLOAD, StandardCharsets.UTF_8) + " ").getBytes(StandardCharsets.UTF_8);
        AgentAdmitException e = assertThrows(AgentAdmitException.class, () ->
            Webhooks.verifySignature(tampered, header, SECRET, Webhooks.DEFAULT_TOLERANCE_SECONDS, NOW));
        assertTrue(e.getMessage().contains("verification failed"));
    }

    @Test
    void wrongSecretFails() throws Exception {
        String header = sign(PAYLOAD, "whsec_other456", NOW);
        assertThrows(AgentAdmitException.class, () ->
            Webhooks.verifySignature(PAYLOAD, header, SECRET, Webhooks.DEFAULT_TOLERANCE_SECONDS, NOW));
    }

    @Test
    void staleTimestampFails() throws Exception {
        String header = sign(PAYLOAD, SECRET, NOW - 600);
        AgentAdmitException e = assertThrows(AgentAdmitException.class, () ->
            Webhooks.verifySignature(PAYLOAD, header, SECRET, Webhooks.DEFAULT_TOLERANCE_SECONDS, NOW));
        assertTrue(e.getMessage().contains("tolerance"));
    }

    @Test
    void futureTimestampFails() throws Exception {
        String header = sign(PAYLOAD, SECRET, NOW + 600);
        assertThrows(AgentAdmitException.class, () ->
            Webhooks.verifySignature(PAYLOAD, header, SECRET, Webhooks.DEFAULT_TOLERANCE_SECONDS, NOW));
    }

    @Test
    void withinTolerancePasses() throws Exception {
        String header = sign(PAYLOAD, SECRET, NOW - 200);
        assertDoesNotThrow(() ->
            Webhooks.verifySignature(PAYLOAD, header, SECRET, Webhooks.DEFAULT_TOLERANCE_SECONDS, NOW));
    }

    @Test
    void toleranceZeroDisablesTimestampCheck() throws Exception {
        String header = sign(PAYLOAD, SECRET, NOW - 99999);
        assertDoesNotThrow(() -> Webhooks.verifySignature(PAYLOAD, header, SECRET, 0, NOW));
    }

    @Test
    void missingHeaderFails() {
        assertThrows(AgentAdmitException.class, () ->
            Webhooks.verifySignature(PAYLOAD, "", SECRET, Webhooks.DEFAULT_TOLERANCE_SECONDS, NOW));
    }

    @Test
    void malformedHeaderFails() {
        for (String header : new String[]{"nonsense", "t=abc,v1=def", "t=123", "v1=abc"}) {
            AgentAdmitException e = assertThrows(AgentAdmitException.class, () ->
                Webhooks.verifySignature(PAYLOAD, header, SECRET, Webhooks.DEFAULT_TOLERANCE_SECONDS, NOW),
                "header: " + header);
            assertTrue(e.getMessage().contains("Malformed"), "header: " + header);
        }
    }

    @Test
    void missingSecretFails() throws Exception {
        String header = sign(PAYLOAD, SECRET, NOW);
        assertThrows(AgentAdmitException.class, () ->
            Webhooks.verifySignature(PAYLOAD, header, "", Webhooks.DEFAULT_TOLERANCE_SECONDS, NOW));
    }

    @Test
    void multipleCandidatesAnyMatchPasses() throws Exception {
        String header = sign(PAYLOAD, SECRET, NOW) + ",v1=deadbeef";
        assertDoesNotThrow(() ->
            Webhooks.verifySignature(PAYLOAD, header, SECRET, Webhooks.DEFAULT_TOLERANCE_SECONDS, NOW));
    }

    @Test
    void booleanFormDoesNotThrow() throws Exception {
        // isValidSignature uses the real clock, so sign with a current timestamp.
        long now = System.currentTimeMillis() / 1000;
        assertTrue(Webhooks.isValidSignature(PAYLOAD, sign(PAYLOAD, SECRET, now), SECRET));
        assertFalse(Webhooks.isValidSignature(PAYLOAD, "t=" + now + ",v1=deadbeef", SECRET));
    }
}
