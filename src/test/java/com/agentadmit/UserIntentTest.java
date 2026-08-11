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
 * Tests for the user-declared intent: the user's own words, typed at the
 * consent moment (distinct from purpose, the app's words). It is a
 * review-time record only, never an enforcement input — authorization
 * decisions ride scopes, connection status, and consent.
 *
 * Outbound (TokensClient.issueToken):
 *   - userIntent(...) includes "user_intent" in the POST /api/v1/apps/{app_id}/token body
 *   - unset or null intent omits the field entirely
 *   - an intent longer than 300 characters throws IllegalArgumentException
 *     before any request is sent
 *
 * Inbound (IntrospectionClient.verify):
 *   - a "user_intent" string on the verify response populates result.userIntent()
 *   - absent intent (older servers) reads as null
 *   - a mistyped intent normalizes to null (metadata tolerance, presence-block convention)
 *     (spoofed/malformed response posture)
 */
class UserIntentTest {

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
    void userIntentIsIncludedInIssueTokenBody() throws Exception {
        CapturingTokensClient client = new CapturingTokensClient();
        client.issueToken("u1", List.of("read:orders"))
            .userIntent("Match my September invoices against the bank statement")
            .send();

        assertEquals("https://api.agentadmit.com/api/v1/apps/app_test/token", client.capturedUrl);
        Map<String, Object> body = MAPPER.readValue(client.capturedBody, Map.class);
        assertEquals("Match my September invoices against the bank statement", body.get("user_intent"));
        assertEquals("u1", body.get("user_id"));
        assertEquals(List.of("read:orders"), body.get("scopes"));
    }

    @Test
    void userIntentIsOmittedWhenNotSet() throws Exception {
        CapturingTokensClient client = new CapturingTokensClient();
        client.issueToken("u1", List.of("read:orders")).send();

        Map<String, Object> body = MAPPER.readValue(client.capturedBody, Map.class);
        assertFalse(body.containsKey("user_intent"), "unset user_intent must be omitted, not null");
    }

    @Test
    void nullUserIntentIsOmitted() throws Exception {
        CapturingTokensClient client = new CapturingTokensClient();
        client.issueToken("u1", List.of("read:orders")).userIntent(null).send();

        Map<String, Object> body = MAPPER.readValue(client.capturedBody, Map.class);
        assertFalse(body.containsKey("user_intent"), "null user_intent must be omitted, not JSON null");
    }

    @Test
    void nullUserIntentClearsAPreviouslySetIntent() throws Exception {
        CapturingTokensClient client = new CapturingTokensClient();
        client.issueToken("u1", List.of("read:orders"))
            .userIntent("Match my September invoices against the bank statement")
            .userIntent(null)
            .send();

        Map<String, Object> body = MAPPER.readValue(client.capturedBody, Map.class);
        assertFalse(body.containsKey("user_intent"));
    }

    @Test
    void userIntentAndPurposeAreIndependentFields() throws Exception {
        CapturingTokensClient client = new CapturingTokensClient();
        client.issueToken("u1", List.of("read:orders"))
            .purpose("Reconcile Q3 invoices")
            .userIntent("Match my September invoices against the bank statement")
            .send();

        Map<String, Object> body = MAPPER.readValue(client.capturedBody, Map.class);
        assertEquals("Reconcile Q3 invoices", body.get("purpose"));
        assertEquals("Match my September invoices against the bank statement", body.get("user_intent"));
    }

    @Test
    void userIntentAtExactly300CharactersIsAccepted() throws Exception {
        String intent = "i".repeat(300);
        CapturingTokensClient client = new CapturingTokensClient();
        client.issueToken("u1", List.of("read:orders")).userIntent(intent).send();

        Map<String, Object> body = MAPPER.readValue(client.capturedBody, Map.class);
        assertEquals(intent, body.get("user_intent"));
    }

    @Test
    void userIntentOver300CharactersIsRejectedBeforeAnyRequest() {
        CapturingTokensClient client = new CapturingTokensClient();
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
            () -> client.issueToken("u1", List.of("read:orders")).userIntent("i".repeat(301)));
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
    void userIntentOnVerifyResponsePopulatesResult() throws Exception {
        String body = "{\"active\":true,\"user_id\":\"u1\",\"connection_id\":\"conn1\","
            + "\"scopes\":[\"read:orders\"],\"agent_label\":\"Bot\","
            + "\"purpose\":\"Reconcile Q3 invoices\","
            + "\"user_intent\":\"Match my September invoices against the bank statement\"}";
        IntrospectionClient.IntrospectionResult result = verifyWithBody(body);
        assertEquals("Match my September invoices against the bank statement", result.userIntent());
        assertEquals("Reconcile Q3 invoices", result.purpose());
        assertEquals("u1", result.userId());
    }

    @Test
    void absentUserIntentIsNull() throws Exception {
        // Older servers omit the field entirely
        String body = "{\"active\":true,\"user_id\":\"u1\",\"connection_id\":\"conn1\","
            + "\"scopes\":[\"read:orders\"],\"agent_label\":\"Bot\"}";
        IntrospectionClient.IntrospectionResult result = verifyWithBody(body);
        assertNull(result.userIntent());
    }

    @Test
    void nullUserIntentOnVerifyResponseIsNull() throws Exception {
        String body = "{\"active\":true,\"user_id\":\"u1\",\"connection_id\":\"conn1\","
            + "\"scopes\":[\"read:orders\"],\"user_intent\":null}";
        IntrospectionClient.IntrospectionResult result = verifyWithBody(body);
        assertNull(result.userIntent());
    }

    @Test
    void mistypedUserIntentIsTreatedAsAbsent() throws Exception {
        // User-declared intent is metadata, never an enforcement input — it
        // follows the presence-block tolerance convention (absent or
        // malformed -> null), not the identity-field strictness. Mirrors how
        // purpose normalizes a non-string value.
        String body = "{\"active\":true,\"user_id\":\"u1\",\"connection_id\":\"conn1\","
            + "\"scopes\":[\"read:orders\"],\"user_intent\":42}";
        IntrospectionClient.IntrospectionResult result = verifyWithBody(body);
        assertNull(result.userIntent(), "Malformed user_intent must normalize to null, not fail verify");
    }
}
