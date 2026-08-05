package com.agentadmit;

import com.fasterxml.jackson.databind.ObjectMapper;
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
 * Tests for the declared purpose: the user-facing reason recorded on the
 * grant at the consent moment. It is a review-time record only, never an
 * enforcement input — authorization decisions ride scopes, connection
 * status, and consent.
 *
 * Outbound (TokensClient.issueToken):
 *   - purpose(...) includes "purpose" in the POST /api/v1/apps/{app_id}/token body
 *   - unset or null purpose omits the field entirely
 *   - a purpose longer than 300 characters throws IllegalArgumentException
 *     before any request is sent
 *
 * Inbound (IntrospectionClient.verify):
 *   - a "purpose" string on the verify response populates result.purpose()
 *   - absent purpose (older servers) reads as null
 *   - a mistyped purpose is rejected like every other string field
 *     (spoofed/malformed response posture)
 */
class DeclaredPurposeTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static HttpResponse<String> stubResponse(int status, String body) {
        HttpHeaders headers = HttpHeaders.of(Map.of(), (a, b) -> true);
        return new HttpResponse<>() {
            @Override public int statusCode() { return status; }
            @Override public HttpRequest request() { return null; }
            @Override public Optional<HttpResponse<String>> previousResponse() { return Optional.empty(); }
            @Override public HttpHeaders headers() { return headers; }
            @Override public String body() { return body; }
            @Override public Optional<SSLSession> sslSession() { return Optional.empty(); }
            @Override public URI uri() { return URI.create("https://agentadmit.example/api/v1/verify"); }
            @Override public HttpClient.Version version() { return HttpClient.Version.HTTP_1_1; }
        };
    }

    private static AgentAdmitConfig configWith() {
        AgentAdmitConfig config = new AgentAdmitConfig();
        config.setApiKey("aa_test_dummy");
        config.setAppId("app_test");
        return config;
    }

    // -------------------------------------------------------------------------
    // Outbound: issueToken request body
    // -------------------------------------------------------------------------

    /** Captures the outbound JSON body instead of sending it. */
    private static class CapturingTokensClient extends TokensClient {
        String capturedUrl;
        String capturedBody;

        CapturingTokensClient() {
            super(configWith());
        }

        @Override
        HttpResponse<String> sendPost(String url, String jsonBody) {
            this.capturedUrl = url;
            this.capturedBody = jsonBody;
            return stubResponse(200, "{\"token\":\"ag_ct_dummy\",\"ok\":true}");
        }
    }

    @Test
    void purposeIsIncludedInIssueTokenBody() throws Exception {
        CapturingTokensClient client = new CapturingTokensClient();
        client.issueToken("u1", List.of("read:orders"))
            .purpose("Reconcile Q3 invoices")
            .send();

        assertEquals("https://api.agentadmit.com/api/v1/apps/app_test/token", client.capturedUrl);
        Map<String, Object> body = MAPPER.readValue(client.capturedBody, Map.class);
        assertEquals("Reconcile Q3 invoices", body.get("purpose"));
        assertEquals("u1", body.get("user_id"));
        assertEquals(List.of("read:orders"), body.get("scopes"));
    }

    @Test
    void purposeIsOmittedWhenNotSet() throws Exception {
        CapturingTokensClient client = new CapturingTokensClient();
        client.issueToken("u1", List.of("read:orders")).send();

        Map<String, Object> body = MAPPER.readValue(client.capturedBody, Map.class);
        assertFalse(body.containsKey("purpose"), "unset purpose must be omitted, not null");
    }

    @Test
    void nullPurposeIsOmitted() throws Exception {
        CapturingTokensClient client = new CapturingTokensClient();
        client.issueToken("u1", List.of("read:orders")).purpose(null).send();

        Map<String, Object> body = MAPPER.readValue(client.capturedBody, Map.class);
        assertFalse(body.containsKey("purpose"), "null purpose must be omitted, not JSON null");
    }

    @Test
    void nullPurposeClearsAPreviouslySetPurpose() throws Exception {
        CapturingTokensClient client = new CapturingTokensClient();
        client.issueToken("u1", List.of("read:orders"))
            .purpose("Reconcile Q3 invoices")
            .purpose(null)
            .send();

        Map<String, Object> body = MAPPER.readValue(client.capturedBody, Map.class);
        assertFalse(body.containsKey("purpose"));
    }

    @Test
    void purposeAtExactly300CharactersIsAccepted() throws Exception {
        String purpose = "p".repeat(300);
        CapturingTokensClient client = new CapturingTokensClient();
        client.issueToken("u1", List.of("read:orders")).purpose(purpose).send();

        Map<String, Object> body = MAPPER.readValue(client.capturedBody, Map.class);
        assertEquals(purpose, body.get("purpose"));
    }

    @Test
    void purposeOver300CharactersIsRejectedBeforeAnyRequest() {
        CapturingTokensClient client = new CapturingTokensClient();
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
            () -> client.issueToken("u1", List.of("read:orders")).purpose("p".repeat(301)));
        assertTrue(ex.getMessage().contains("300"), "Error should state the 300-character limit");
        assertNull(client.capturedBody, "Validation must fail before any request is sent");
    }

    // -------------------------------------------------------------------------
    // Inbound: verify response parsing
    // -------------------------------------------------------------------------

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

    private static IntrospectionClient.IntrospectionResult verifyWithBody(String body) throws Exception {
        return new OneResponseIntrospectionClient(stubResponse(200, body)).verify("ag_at_dummy");
    }

    @Test
    void purposeOnVerifyResponsePopulatesResult() throws Exception {
        String body = "{\"active\":true,\"user_id\":\"u1\",\"connection_id\":\"conn1\","
            + "\"scopes\":[\"read:orders\"],\"agent_label\":\"Bot\","
            + "\"purpose\":\"Reconcile Q3 invoices\"}";
        IntrospectionClient.IntrospectionResult result = verifyWithBody(body);
        assertEquals("Reconcile Q3 invoices", result.purpose());
        assertEquals("u1", result.userId());
    }

    @Test
    void absentPurposeIsNull() throws Exception {
        // Older servers omit the field entirely
        String body = "{\"active\":true,\"user_id\":\"u1\",\"connection_id\":\"conn1\","
            + "\"scopes\":[\"read:orders\"],\"agent_label\":\"Bot\"}";
        IntrospectionClient.IntrospectionResult result = verifyWithBody(body);
        assertNull(result.purpose());
    }

    @Test
    void nullPurposeOnVerifyResponseIsNull() throws Exception {
        String body = "{\"active\":true,\"user_id\":\"u1\",\"connection_id\":\"conn1\","
            + "\"scopes\":[\"read:orders\"],\"purpose\":null}";
        IntrospectionClient.IntrospectionResult result = verifyWithBody(body);
        assertNull(result.purpose());
    }

    @Test
    void mistypedPurposeIsRejected() {
        // Same strict string typing as user_id/connection_id: a non-string
        // value indicates a spoofed or malformed response.
        String body = "{\"active\":true,\"user_id\":\"u1\",\"connection_id\":\"conn1\","
            + "\"scopes\":[\"read:orders\"],\"purpose\":42}";
        AgentAdmitException ex = assertThrows(AgentAdmitException.class,
            () -> verifyWithBody(body));
        assertEquals(401, ex.getStatusCode());
        assertTrue(ex.getMessage().contains("purpose"), "Error should identify the bad field");
    }
}
