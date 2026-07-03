package com.agentadmit;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

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
 * Tests for M4 introspection response validation and M4 2xx-only acceptance.
 *
 * Only responses with HTTP 2xx status AND active=true (strictly Boolean) AND
 * well-typed fields (user_id/agent_id/connection_id as strings, scopes as
 * list of strings) should be treated as valid.
 */
class IntrospectionValidationTest {

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

    private static class OneResponseClient extends IntrospectionClient {
        private final HttpResponse<String> response;

        OneResponseClient(HttpResponse<String> response) {
            super(configWith());
            this.response = response;
        }

        private static AgentAdmitConfig configWith() {
            AgentAdmitConfig config = new AgentAdmitConfig();
            config.setApiKey("aa_test_dummy");
            return config;
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

    private static final String VALID_BODY =
        "{\"active\":true,\"user_id\":\"u1\",\"connection_id\":\"conn1\","
        + "\"scopes\":[\"read:orders\"],\"agent_label\":\"Bot\"}";

    // -------------------------------------------------------------------------
    // 2xx acceptance
    // -------------------------------------------------------------------------

    @ParameterizedTest
    @ValueSource(ints = {200, 201, 204})
    void twoxxStatusWithActiveTokenIsAccepted(int status) throws Exception {
        // 204 has no body but we still test that 2xx passes the status check
        // (it will fail body parsing, but 204 is unusual here; 200/201 are the real cases)
        if (status == 204) {
            // 204 -> no body -> body parse error -> 502, but the status check must not throw 502 for "not 200"
            OneResponseClient client = new OneResponseClient(stubResponse(status, "{}"));
            AgentAdmitException ex = assertThrows(AgentAdmitException.class,
                () -> client.verify("ag_at_dummy"));
            // Should fail at active check (active absent => not active), not a "service returned 204" 502
            assertNotEquals(502, ex.getStatusCode(), "2xx status should not be rejected as a service error");
            return;
        }
        OneResponseClient client = new OneResponseClient(stubResponse(status, VALID_BODY));
        IntrospectionClient.IntrospectionResult result = assertDoesNotThrow(
            () -> client.verify("ag_at_dummy"));
        assertEquals("u1", result.userId());
    }

    @ParameterizedTest
    @ValueSource(ints = {400, 403, 404, 500, 502, 503})
    void nonTwoxxNon401StatusIsRejectedAs502(int status) {
        OneResponseClient client = new OneResponseClient(stubResponse(status, "{\"error\":\"some_error\"}"));
        AgentAdmitException ex = assertThrows(AgentAdmitException.class,
            () -> client.verify("ag_at_dummy"));
        assertEquals(502, ex.getStatusCode(), "Non-2xx status " + status + " should map to 502");
    }

    // -------------------------------------------------------------------------
    // active field strict validation
    // -------------------------------------------------------------------------

    @Test
    void activeFalseIsRejected() {
        String body = "{\"active\":false,\"user_id\":\"u1\",\"scopes\":[]}";
        OneResponseClient client = new OneResponseClient(stubResponse(200, body));
        AgentAdmitException ex = assertThrows(AgentAdmitException.class,
            () -> client.verify("ag_at_dummy"));
        assertEquals(401, ex.getStatusCode());
        assertTrue(ex.getMessage().contains("not active"));
    }

    @Test
    void activeNullIsRejected() {
        String body = "{\"active\":null,\"user_id\":\"u1\",\"scopes\":[]}";
        OneResponseClient client = new OneResponseClient(stubResponse(200, body));
        AgentAdmitException ex = assertThrows(AgentAdmitException.class,
            () -> client.verify("ag_at_dummy"));
        assertEquals(401, ex.getStatusCode());
    }

    @Test
    void activeMissingIsRejected() {
        String body = "{\"user_id\":\"u1\",\"scopes\":[]}";
        OneResponseClient client = new OneResponseClient(stubResponse(200, body));
        AgentAdmitException ex = assertThrows(AgentAdmitException.class,
            () -> client.verify("ag_at_dummy"));
        assertEquals(401, ex.getStatusCode());
    }

    @Test
    void activeAsStringTrueIsRejected() {
        // String "true" must not be accepted as Boolean true
        String body = "{\"active\":\"true\",\"user_id\":\"u1\",\"scopes\":[]}";
        OneResponseClient client = new OneResponseClient(stubResponse(200, body));
        AgentAdmitException ex = assertThrows(AgentAdmitException.class,
            () -> client.verify("ag_at_dummy"));
        assertEquals(401, ex.getStatusCode());
    }

    // -------------------------------------------------------------------------
    // Field type validation
    // -------------------------------------------------------------------------

    @Test
    void userIdAsIntegerIsRejected() {
        String body = "{\"active\":true,\"user_id\":42,\"connection_id\":\"conn1\","
            + "\"scopes\":[\"read:orders\"]}";
        OneResponseClient client = new OneResponseClient(stubResponse(200, body));
        AgentAdmitException ex = assertThrows(AgentAdmitException.class,
            () -> client.verify("ag_at_dummy"));
        assertEquals(401, ex.getStatusCode());
        assertTrue(ex.getMessage().contains("user_id"), "Error should identify the bad field");
    }

    @Test
    void connectionIdAsIntegerIsRejected() {
        String body = "{\"active\":true,\"user_id\":\"u1\",\"connection_id\":99,"
            + "\"scopes\":[\"read:orders\"]}";
        OneResponseClient client = new OneResponseClient(stubResponse(200, body));
        AgentAdmitException ex = assertThrows(AgentAdmitException.class,
            () -> client.verify("ag_at_dummy"));
        assertEquals(401, ex.getStatusCode());
        assertTrue(ex.getMessage().contains("connection_id"));
    }

    @Test
    void scopesAsStringIsRejected() {
        String body = "{\"active\":true,\"user_id\":\"u1\",\"connection_id\":\"c1\","
            + "\"scopes\":\"read:orders\"}";
        OneResponseClient client = new OneResponseClient(stubResponse(200, body));
        AgentAdmitException ex = assertThrows(AgentAdmitException.class,
            () -> client.verify("ag_at_dummy"));
        assertEquals(401, ex.getStatusCode());
        assertTrue(ex.getMessage().contains("scopes"));
    }

    @Test
    void scopesWithNonStringElementIsRejected() {
        String body = "{\"active\":true,\"user_id\":\"u1\",\"connection_id\":\"c1\","
            + "\"scopes\":[\"read:orders\",42]}";
        OneResponseClient client = new OneResponseClient(stubResponse(200, body));
        AgentAdmitException ex = assertThrows(AgentAdmitException.class,
            () -> client.verify("ag_at_dummy"));
        assertEquals(401, ex.getStatusCode());
        assertTrue(ex.getMessage().contains("scopes"));
    }

    @Test
    void wellFormedResponseIsAccepted() throws Exception {
        OneResponseClient client = new OneResponseClient(stubResponse(200, VALID_BODY));
        IntrospectionClient.IntrospectionResult result = client.verify("ag_at_dummy");
        assertEquals("u1", result.userId());
        assertEquals("conn1", result.connectionId());
        assertEquals(List.of("read:orders"), result.scopes());
        assertEquals("Bot", result.agentLabel());
    }

    @Test
    void missingConnectionIdIsAccepted() throws Exception {
        // connection_id is optional in some token types
        String body = "{\"active\":true,\"user_id\":\"u1\","
            + "\"scopes\":[\"read:data\"],\"agent_label\":\"Agent\"}";
        OneResponseClient client = new OneResponseClient(stubResponse(200, body));
        IntrospectionClient.IntrospectionResult result = client.verify("ag_at_dummy");
        assertEquals("u1", result.userId());
        assertNull(result.connectionId());
    }

    @Test
    void emptyScopesListIsAccepted() throws Exception {
        String body = "{\"active\":true,\"user_id\":\"u1\","
            + "\"connection_id\":\"c1\",\"scopes\":[]}";
        OneResponseClient client = new OneResponseClient(stubResponse(200, body));
        IntrospectionClient.IntrospectionResult result = client.verify("ag_at_dummy");
        assertEquals(List.of(), result.scopes());
    }
}
