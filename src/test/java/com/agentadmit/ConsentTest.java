package com.agentadmit;

import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLSession;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for Consent Ledger behavior: ConsentClient.checkConsent parsing and
 * error handling, and the IntrospectionResult.consentGranted() verdict matrix.
 *
 * consentGranted() must fail closed: only a verdict whose "granted" field is
 * exactly Boolean.TRUE grants. A consent map that is present but malformed
 * (granted missing or not a boolean) is denied, and a fully absent map is
 * NEVER a grant — the hosted service omits the block when its consent-store
 * read fails (degraded mode), so absence is resolved through the Consent
 * Ledger (as CallerConsentFilter does) or denied.
 */
class ConsentTest {

    private static HttpResponse<String> stubResponse(int status, String body) {
        HttpHeaders headers = HttpHeaders.of(Map.of(), (a, b) -> true);
        return new HttpResponse<>() {
            @Override public int statusCode() { return status; }
            @Override public HttpRequest request() { return null; }
            @Override public Optional<HttpResponse<String>> previousResponse() { return Optional.empty(); }
            @Override public HttpHeaders headers() { return headers; }
            @Override public String body() { return body; }
            @Override public Optional<SSLSession> sslSession() { return Optional.empty(); }
            @Override public URI uri() { return URI.create("https://agentadmit.example/api/v1/consent/check"); }
            @Override public HttpClient.Version version() { return HttpClient.Version.HTTP_1_1; }
        };
    }

    private static AgentAdmitConfig configWith() {
        AgentAdmitConfig config = new AgentAdmitConfig();
        config.setApiKey("aa_test_dummy");
        config.setAppId("app_test");
        return config;
    }

    private static class OneResponseConsentClient extends ConsentClient {
        private final HttpResponse<String> response;

        OneResponseConsentClient(HttpResponse<String> response) {
            super(configWith());
            this.response = response;
        }

        @Override
        HttpResponse<String> sendConsentRequest(HttpRequest request) {
            return response;
        }
    }

    private static class OneResponseIntrospectionClient extends IntrospectionClient {
        private final HttpResponse<String> response;

        OneResponseIntrospectionClient(HttpResponse<String> response) {
            super(configWith());
            this.response = response;
        }

        @Override
        HttpResponse<String> sendIntrospectionRequest(String token) {
            return response;
        }

        @Override
        void sleepBeforeRetry(long ms) {
            // no-op in tests
        }
    }

    // -------------------------------------------------------------------------
    // ConsentClient.checkConsent
    // -------------------------------------------------------------------------

    @Test
    void checkConsentParsesVerdictOn200() throws Exception {
        String body = "{\"granted\":true,\"caller_class\":\"in_app_ai\","
            + "\"scope_group\":null,\"source\":\"class_default\","
            + "\"evaluated_at\":\"2026-07-03T00:00:00Z\"}";
        OneResponseConsentClient client = new OneResponseConsentClient(stubResponse(200, body));
        Map<String, Object> verdict = client.checkConsent(
            "user_1", ConsentClient.CALLER_CLASS_IN_APP_AI, null);
        assertEquals(Boolean.TRUE, verdict.get("granted"));
        assertEquals("in_app_ai", verdict.get("caller_class"));
        assertEquals("class_default", verdict.get("source"));
    }

    @Test
    void checkConsentParsesDeniedVerdictOn200() throws Exception {
        String body = "{\"granted\":false,\"caller_class\":\"external_agent\","
            + "\"source\":\"user_switch\"}";
        OneResponseConsentClient client = new OneResponseConsentClient(stubResponse(200, body));
        Map<String, Object> verdict = client.checkConsent(
            "user_1", ConsentClient.CALLER_CLASS_EXTERNAL_AGENT, null);
        assertEquals(Boolean.FALSE, verdict.get("granted"));
    }

    @Test
    void checkConsentThrowsOnNon200() {
        OneResponseConsentClient client = new OneResponseConsentClient(
            stubResponse(403, "{\"error\":\"forbidden\"}"));
        AgentAdmitException ex = assertThrows(AgentAdmitException.class,
            () -> client.checkConsent("user_1", ConsentClient.CALLER_CLASS_HUMAN_SESSION, null));
        assertEquals(403, ex.getStatusCode());
    }

    @Test
    void checkConsentThrowsOnServerError() {
        OneResponseConsentClient client = new OneResponseConsentClient(
            stubResponse(500, "{\"error\":\"internal\"}"));
        AgentAdmitException ex = assertThrows(AgentAdmitException.class,
            () -> client.checkConsent("user_1", ConsentClient.CALLER_CLASS_IN_APP_AI, null));
        assertEquals(500, ex.getStatusCode());
    }

    @Test
    void checkConsentThrowsOnMalformedJsonBody() {
        OneResponseConsentClient client = new OneResponseConsentClient(
            stubResponse(200, "not-json{{{"));
        AgentAdmitException ex = assertThrows(AgentAdmitException.class,
            () -> client.checkConsent("user_1", ConsentClient.CALLER_CLASS_IN_APP_AI, null));
        assertEquals(502, ex.getStatusCode());
    }

    @Test
    void checkConsentRejectsUnknownCallerClass() {
        OneResponseConsentClient client = new OneResponseConsentClient(
            stubResponse(200, "{\"granted\":true}"));
        AgentAdmitException ex = assertThrows(AgentAdmitException.class,
            () -> client.checkConsent("user_1", "robot_overlord", null));
        assertEquals(400, ex.getStatusCode());
    }

    // -------------------------------------------------------------------------
    // consentGranted() matrix via the record directly
    // -------------------------------------------------------------------------

    private static IntrospectionClient.IntrospectionResult resultWithConsent(Map<String, Object> consent) {
        return new IntrospectionClient.IntrospectionResult(
            "u1", "conn1", List.of("read:orders"), "Bot",
            null, null, null, null, 0L, consent, null, null, null);
    }

    @Test
    void consentAbsentIsDenied() {
        // Absent consent map is NEVER a grant: the hosted service omits the
        // block when its consent-store read fails (degraded mode). Callers
        // that need a verdict resolve absence through the Consent Ledger, as
        // CallerConsentFilter does; consentGranted() itself fails closed.
        assertFalse(resultWithConsent(null).consentGranted());
    }

    @Test
    void consentGrantedTrueIsGranted() {
        assertTrue(resultWithConsent(Map.of("granted", Boolean.TRUE)).consentGranted());
    }

    @Test
    void consentGrantedFalseIsDenied() {
        assertFalse(resultWithConsent(Map.of("granted", Boolean.FALSE)).consentGranted());
    }

    @Test
    void consentGrantedStringTrueIsDenied() {
        // String "true" must not be accepted as Boolean true (fail closed)
        assertFalse(resultWithConsent(Map.of("granted", "true")).consentGranted());
    }

    @Test
    void consentGrantedIntegerOneIsDenied() {
        assertFalse(resultWithConsent(Map.of("granted", 1)).consentGranted());
    }

    @Test
    void consentGrantedNullIsDenied() {
        java.util.Map<String, Object> consent = new java.util.HashMap<>();
        consent.put("granted", null);
        assertFalse(resultWithConsent(consent).consentGranted());
    }

    @Test
    void consentPresentWithoutGrantedFieldIsDenied() {
        assertFalse(resultWithConsent(Map.of("caller_class", "external_agent")).consentGranted());
    }

    // -------------------------------------------------------------------------
    // consentGranted() matrix end to end through IntrospectionClient.verify
    // -------------------------------------------------------------------------

    private static IntrospectionClient.IntrospectionResult verifyWithBody(String body) throws Exception {
        OneResponseIntrospectionClient client =
            new OneResponseIntrospectionClient(stubResponse(200, body));
        return client.verify("ag_at_dummy");
    }

    private static String verifyBodyWithConsent(String consentJson) {
        String base = "{\"active\":true,\"user_id\":\"u1\",\"connection_id\":\"conn1\","
            + "\"scopes\":[\"read:orders\"],\"agent_label\":\"Bot\"";
        return consentJson == null ? base + "}" : base + ",\"consent\":" + consentJson + "}";
    }

    @Test
    void verifyWithoutConsentFieldIsDenied() throws Exception {
        // Degraded-mode/legacy server response with no consent key at all:
        // never a grant. consent() stays null so a consumer can distinguish
        // "absent — resolve via the Consent Ledger" from an explicit denial.
        IntrospectionClient.IntrospectionResult result = verifyWithBody(verifyBodyWithConsent(null));
        assertNull(result.consent());
        assertFalse(result.consentGranted());
    }

    @Test
    void verifyWithGrantedTrueIsGranted() throws Exception {
        assertTrue(verifyWithBody(verifyBodyWithConsent("{\"granted\":true}")).consentGranted());
    }

    @Test
    void verifyWithGrantedFalseIsDenied() throws Exception {
        assertFalse(verifyWithBody(verifyBodyWithConsent("{\"granted\":false}")).consentGranted());
    }

    @Test
    void verifyWithGrantedStringTrueIsDenied() throws Exception {
        // Malformed verdict must not be silently dropped and read as allowed
        assertFalse(verifyWithBody(verifyBodyWithConsent("{\"granted\":\"true\"}")).consentGranted());
    }

    @Test
    void verifyWithGrantedIntegerOneIsDenied() throws Exception {
        assertFalse(verifyWithBody(verifyBodyWithConsent("{\"granted\":1}")).consentGranted());
    }

    @Test
    void verifyWithGrantedNullIsDenied() throws Exception {
        assertFalse(verifyWithBody(verifyBodyWithConsent("{\"granted\":null}")).consentGranted());
    }

    @Test
    void verifyWithEmptyConsentMapIsDenied() throws Exception {
        assertFalse(verifyWithBody(verifyBodyWithConsent("{}")).consentGranted());
    }
}
