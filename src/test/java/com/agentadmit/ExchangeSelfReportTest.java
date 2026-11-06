package com.agentadmit;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLSession;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * TokensClient.exchange (1.14.1): what the agent says it runs on
 * (agent_platform, agent_model) is passed along to the hosted exchange when
 * given and omitted when not. The exchange goes through its own
 * unauthenticated send, never the API-key path.
 */
class ExchangeSelfReportTest {

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
            @Override public URI uri() { return URI.create("https://agentadmit.example/api/v1/exchange"); }
            @Override public HttpClient.Version version() { return HttpClient.Version.HTTP_1_1; }
        };
    }

    private static class CapturingTokensClient extends TokensClient {
        String exchangeUrl;
        String exchangeBody;
        boolean authenticatedPostUsed;
        int status = 200;

        CapturingTokensClient() {
            super(config());
        }

        private static AgentAdmitConfig config() {
            AgentAdmitConfig config = new AgentAdmitConfig();
            config.setApiKey("aa_test_dummy");
            config.setAppId("app_test");
            return config;
        }

        @Override
        HttpResponse<String> sendExchange(String url, String jsonBody) {
            this.exchangeUrl = url;
            this.exchangeBody = jsonBody;
            return stubResponse(status, "{\"access_token\":\"ag_at_x\",\"connection_id\":\"conn_1\"}");
        }

        @Override
        HttpResponse<String> sendPost(String url, String jsonBody) {
            this.authenticatedPostUsed = true;
            return stubResponse(200, "{}");
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> body(CapturingTokensClient client) throws Exception {
        return MAPPER.readValue(client.exchangeBody, Map.class);
    }

    @Test
    void bareExchangeSendsOnlyTheTokenOnTheUnauthenticatedPath() throws Exception {
        CapturingTokensClient client = new CapturingTokensClient();
        Map<String, Object> result = client.exchange("ag_ct_abc", null, null);

        assertEquals("ag_at_x", result.get("access_token"));
        assertEquals("https://api.agentadmit.com/api/v1/exchange", client.exchangeUrl);
        assertEquals(Map.of("token", "ag_ct_abc"), body(client));
        assertFalse(client.authenticatedPostUsed, "the exchange never goes through the API-key path");
    }

    @Test
    void forwardsWhatTheAgentSaysItRunsOn() throws Exception {
        CapturingTokensClient client = new CapturingTokensClient();
        client.exchange("ag_ct_abc", "My Agent", null, "ExampleAgent 2.1",
            new AgentReported.Model("example-model", "2026-01"));

        assertEquals(
            Map.of(
                "token", "ag_ct_abc",
                "agent_label", "My Agent",
                "agent_platform", "ExampleAgent 2.1",
                "agent_model", Map.of("id", "example-model", "version", "2026-01")),
            body(client));
    }

    @Test
    void modelWithoutVersionOmitsVersionAndNullsAreOmitted() throws Exception {
        CapturingTokensClient client = new CapturingTokensClient();
        client.exchange("ag_ct_abc", null, "agent_1", null, new AgentReported.Model("example-model", null));

        assertEquals(
            Map.of("token", "ag_ct_abc", "agent_id", "agent_1", "agent_model", Map.of("id", "example-model")),
            body(client));
        assertFalse(client.exchangeBody.contains("null"), "no explicit JSON nulls reach the hosted service");
    }

    @Test
    void threeArgumentExchangeFromBefore1141StillWorks() throws Exception {
        CapturingTokensClient client = new CapturingTokensClient();
        client.exchange("ag_ct_abc", "My Agent", "agent_1");

        assertEquals(
            Map.of("token", "ag_ct_abc", "agent_label", "My Agent", "agent_id", "agent_1"),
            body(client));
    }

    @Test
    void hostedErrorStillThrowsWithItsStatus() {
        CapturingTokensClient client = new CapturingTokensClient();
        client.status = 401;
        AgentAdmitException e = assertThrows(AgentAdmitException.class,
            () -> client.exchange("ag_ct_used", null, null));
        assertEquals(401, e.getStatusCode());
    }
}
