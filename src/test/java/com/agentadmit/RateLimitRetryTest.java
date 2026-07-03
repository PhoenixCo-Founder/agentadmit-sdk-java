package com.agentadmit;

import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLSession;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Regression tests for 429 retry handling in IntrospectionClient#verify.
 *
 * A server-supplied Retry-After header is untrusted input: a compromised or
 * misconfigured endpoint could send {@code Retry-After: 3600} and pin the
 * caller's request thread for an hour. Every wait must be capped at 30
 * seconds, and cumulative wait across retries of one verify call must be
 * capped at 120 seconds.
 */
class RateLimitRetryTest {

    /** Minimal HttpResponse stub with a status code, headers, and body. */
    private static HttpResponse<String> stubResponse(int status, Map<String, List<String>> headers, String body) {
        HttpHeaders parsed = HttpHeaders.of(headers, (a, b) -> true);
        return new HttpResponse<>() {
            @Override public int statusCode() { return status; }
            @Override public HttpRequest request() { return null; }
            @Override public Optional<HttpResponse<String>> previousResponse() { return Optional.empty(); }
            @Override public HttpHeaders headers() { return parsed; }
            @Override public String body() { return body; }
            @Override public Optional<SSLSession> sslSession() { return Optional.empty(); }
            @Override public URI uri() { return URI.create("https://agentadmit.example/api/v1/verify"); }
            @Override public HttpClient.Version version() { return HttpClient.Version.HTTP_1_1; }
        };
    }

    private static HttpResponse<String> rateLimited(String retryAfter) {
        return stubResponse(429, Map.of("Retry-After", List.of(retryAfter)), "{\"error\":\"rate_limited\"}");
    }

    private static HttpResponse<String> ok() {
        return stubResponse(200, Map.of(),
            "{\"active\":true,\"user_id\":\"user_1\",\"connection_id\":\"conn_1\","
                + "\"scopes\":[\"read:things\"],\"agent_label\":\"Test Agent\"}");
    }

    /** Client whose HTTP layer replays canned responses and records sleeps. */
    private static class StubbedClient extends IntrospectionClient {
        final List<Long> sleeps = new ArrayList<>();
        final List<HttpResponse<String>> responses;
        int calls = 0;

        StubbedClient(int maxRetries, List<HttpResponse<String>> responses) {
            super(configWith(maxRetries));
            this.responses = responses;
        }

        private static AgentAdmitConfig configWith(int maxRetries) {
            AgentAdmitConfig config = new AgentAdmitConfig();
            config.setApiKey("aa_test_dummy");
            config.setMaxRetries(maxRetries);
            return config;
        }

        @Override
        HttpResponse<String> sendIntrospectionRequest(String token) {
            HttpResponse<String> response = responses.get(Math.min(calls, responses.size() - 1));
            calls++;
            return response;
        }

        @Override
        void sleepBeforeRetry(long totalWaitMs) {
            sleeps.add(totalWaitMs);
        }
    }

    @Test
    void hugeRetryAfterIsCappedAt30s() {
        StubbedClient client = new StubbedClient(3, List.of(rateLimited("3600")));

        AgentAdmitException.RateLimitError error = assertThrows(
            AgentAdmitException.RateLimitError.class,
            () -> client.verify("ag_at_dummy"));

        assertTrue(error.getMessage().contains("Max retries"), error.getMessage());
        assertEquals(3, client.sleeps.size());
        for (long slept : client.sleeps) {
            assertTrue(slept <= 30_500L,
                "wait must be capped at 30s + jitter, got " + slept + "ms — Retry-After was not capped");
        }
    }

    @Test
    void cumulativeBudgetExhausted() {
        // High max_retries so the 120s budget, not the retry count, is the limiter.
        StubbedClient client = new StubbedClient(99, List.of(rateLimited("30")));

        AgentAdmitException.RateLimitError error = assertThrows(
            AgentAdmitException.RateLimitError.class,
            () -> client.verify("ag_at_dummy"));

        assertTrue(error.getMessage().contains("budget"), error.getMessage());
        // ~30s + jitter per wait -> exactly 3 sleeps before the 4th would
        // blow the 120s budget.
        assertEquals(3, client.sleeps.size());
        assertEquals(4, client.calls);
    }

    @Test
    void recoversWhenServerStopsRateLimiting() throws Exception {
        StubbedClient client = new StubbedClient(3, List.of(rateLimited("2"), ok()));

        IntrospectionClient.IntrospectionResult result = client.verify("ag_at_dummy");

        assertEquals("conn_1", result.connectionId());
        assertEquals(List.of("read:things"), result.scopes());
        assertEquals(2, client.calls);
        assertEquals(1, client.sleeps.size());
        assertTrue(client.sleeps.get(0) <= 2_500L);
    }
}
