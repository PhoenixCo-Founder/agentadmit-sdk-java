package com.agentadmit;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import javax.net.ssl.SSLSession;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Outcome reporting (SDK 1.13.0): successful verify responses can carry the
 * source {@code audit_row_id}; apps can explicitly report
 * executed/failed/unknown outcomes, and the filter can optionally report the
 * observed response class after the downstream app response completes.
 */
class OutcomeReportingTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String AUDIT_ROW = "11111111-1111-4111-8111-111111111111";

    private static AgentAdmitConfig configWith() {
        AgentAdmitConfig config = new AgentAdmitConfig();
        config.setApiKey("aa_test_dummy");
        config.setApiUrl("https://agentadmit.example");
        return config;
    }

    private static HttpResponse<String> stubResponse(int status, String body) {
        HttpHeaders headers = HttpHeaders.of(Map.of(), (a, b) -> true);
        return new HttpResponse<>() {
            @Override public int statusCode() { return status; }
            @Override public HttpRequest request() { return null; }
            @Override public Optional<HttpResponse<String>> previousResponse() { return Optional.empty(); }
            @Override public HttpHeaders headers() { return headers; }
            @Override public String body() { return body; }
            @Override public Optional<SSLSession> sslSession() { return Optional.empty(); }
            @Override public URI uri() { return URI.create("https://agentadmit.example/api"); }
            @Override public HttpClient.Version version() { return HttpClient.Version.HTTP_1_1; }
        };
    }

    private static MockHttpServletRequest agentRequest() {
        MockHttpServletRequest req = new MockHttpServletRequest("POST", "/api/payments");
        req.addHeader("Authorization", "Bearer ag_at_dummy_token");
        return req;
    }

    private static String verifyBodyWithAuditRow(String auditRow) {
        return "{\"active\":true,\"user_id\":\"user_1\",\"connection_id\":\"conn_1\","
            + "\"scopes\":[\"write:payments\"],\"agent_label\":\"Test Agent\","
            + "\"audit_row_id\":\"" + auditRow + "\"}";
    }

    private static final String OUTCOME_RESPONSE =
        "{\"outcome_row_id\":\"22222222-2222-4222-8222-222222222222\","
            + "\"outcome\":\"executed\",\"status_class\":\"2xx\",\"chain_seq\":1042,\"row_hash\":\"hash_222\","
            + "\"reported_at\":\"2026-09-29T21:00:00.000Z\"}";

    private static class CapturingClient extends IntrospectionClient {
        private final HttpResponse<String> verifyResponse;
        private final HttpResponse<String> outcomeResponse;
        Map<String, Object> lastOutcomeBody;
        String lastOutcomeRowId;
        int outcomeCalls;

        CapturingClient(HttpResponse<String> verifyResponse, HttpResponse<String> outcomeResponse) {
            super(configWith());
            this.verifyResponse = verifyResponse;
            this.outcomeResponse = outcomeResponse;
        }

        @Override
        HttpResponse<String> sendIntrospectionRequest(String token, VerifyTelemetry telemetry) {
            return verifyResponse;
        }

        @Override
        @SuppressWarnings("unchecked")
        HttpResponse<String> sendOutcomeRequest(
                String auditRowId, Outcome outcome, StatusClass statusClass) throws AgentAdmitException {
            try {
                lastOutcomeRowId = auditRowId;
                lastOutcomeBody = MAPPER.readValue(buildOutcomeBody(outcome, statusClass), Map.class);
                outcomeCalls++;
                return outcomeResponse;
            } catch (Exception e) {
                throw new AgentAdmitException("test outcome capture failed: " + e.getMessage(), 500);
            }
        }

        @Override
        void sleepBeforeRetry(long ms) {
            // no-op in tests
        }
    }

    @Test
    void verifyParsesAuditRowId() {
        CapturingClient client = new CapturingClient(
            stubResponse(200, verifyBodyWithAuditRow(AUDIT_ROW)),
            stubResponse(201, OUTCOME_RESPONSE));

        IntrospectionClient.IntrospectionResult result = client.verify("ag_at_dummy_token");

        assertEquals(AUDIT_ROW, result.auditRowId());
    }

    @Test
    void reportOutcomePostsExplicitOutcomeAndStatusClass() {
        CapturingClient client = new CapturingClient(
            stubResponse(200, verifyBodyWithAuditRow(AUDIT_ROW)),
            stubResponse(201, OUTCOME_RESPONSE));

        IntrospectionClient.OutcomeReport report = client.reportOutcome(
            AUDIT_ROW,
            IntrospectionClient.Outcome.EXECUTED,
            IntrospectionClient.StatusClass.SUCCESS);

        assertEquals(AUDIT_ROW, client.lastOutcomeRowId);
        assertEquals("executed", client.lastOutcomeBody.get("outcome"));
        assertEquals("2xx", client.lastOutcomeBody.get("status_class"));
        assertEquals("22222222-2222-4222-8222-222222222222", report.outcomeRowId());
        assertEquals(IntrospectionClient.Outcome.EXECUTED, report.outcome());
        assertEquals(IntrospectionClient.StatusClass.SUCCESS, report.statusClass());
        assertEquals(1042L, report.chainSeq());
    }

    @Test
    void unknownOutcomeIsOnlySentWhenExplicitlyRequested() {
        CapturingClient client = new CapturingClient(
            stubResponse(200, verifyBodyWithAuditRow(AUDIT_ROW)),
            stubResponse(200, OUTCOME_RESPONSE.replace("\"executed\"", "\"unknown\"")));

        client.reportOutcome(AUDIT_ROW, IntrospectionClient.Outcome.UNKNOWN);

        assertEquals("unknown", client.lastOutcomeBody.get("outcome"));
        assertFalse(client.lastOutcomeBody.containsKey("status_class"));
    }

    @Test
    void filterReportsExecutedAfterSuccessfulAppResponse() throws Exception {
        CapturingClient client = new CapturingClient(
            stubResponse(200, verifyBodyWithAuditRow(AUDIT_ROW)),
            stubResponse(201, OUTCOME_RESPONSE));
        AgentAdmitFilter filter = new AgentAdmitFilter(
            configWith(), client, r -> "write:payments",
            AgentAdmitFilter.Options.withOutcomeReporting());
        MockHttpServletResponse resp = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain() {
            @Override
            public void doFilter(jakarta.servlet.ServletRequest request,
                                 jakarta.servlet.ServletResponse response)
                    throws IOException {
                ((MockHttpServletResponse) response).setStatus(204);
            }
        };

        filter.doFilter(agentRequest(), resp, chain);

        assertEquals(1, client.outcomeCalls);
        assertEquals(AUDIT_ROW, client.lastOutcomeRowId);
        assertEquals("executed", client.lastOutcomeBody.get("outcome"));
        assertEquals("2xx", client.lastOutcomeBody.get("status_class"));
    }

    @Test
    void filterReportsFailedAfterErrorAppResponse() throws Exception {
        CapturingClient client = new CapturingClient(
            stubResponse(200, verifyBodyWithAuditRow(AUDIT_ROW)),
            stubResponse(201, OUTCOME_RESPONSE.replace("\"executed\"", "\"failed\"")));
        AgentAdmitFilter filter = new AgentAdmitFilter(
            configWith(), client, r -> "write:payments",
            AgentAdmitFilter.Options.withOutcomeReporting());
        MockHttpServletResponse resp = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain() {
            @Override
            public void doFilter(jakarta.servlet.ServletRequest request,
                                 jakarta.servlet.ServletResponse response)
                    throws IOException {
                ((MockHttpServletResponse) response).setStatus(500);
            }
        };

        filter.doFilter(agentRequest(), resp, chain);

        assertEquals("failed", client.lastOutcomeBody.get("outcome"));
        assertEquals("5xx", client.lastOutcomeBody.get("status_class"));
    }

    @Test
    void filterDoesNotReportWhenHandlerAborts() {
        CapturingClient client = new CapturingClient(
            stubResponse(200, verifyBodyWithAuditRow(AUDIT_ROW)),
            stubResponse(201, OUTCOME_RESPONSE));
        AgentAdmitFilter filter = new AgentAdmitFilter(
            configWith(), client, r -> "write:payments",
            AgentAdmitFilter.Options.withOutcomeReporting());
        MockFilterChain chain = new MockFilterChain() {
            @Override
            public void doFilter(jakarta.servlet.ServletRequest request,
                                 jakarta.servlet.ServletResponse response)
                    throws IOException, ServletException {
                throw new ServletException("aborted");
            }
        };

        assertThrows(ServletException.class,
            () -> filter.doFilter(agentRequest(), new MockHttpServletResponse(), chain));
        assertEquals(0, client.outcomeCalls);
    }

    @Test
    void outcomeReportingErrorsDoNotReplaceTheAppResponse() throws Exception {
        CapturingClient client = new CapturingClient(
            stubResponse(200, verifyBodyWithAuditRow(AUDIT_ROW)),
            stubResponse(500, "{\"error\":\"internal_error\"}"));
        AgentAdmitFilter filter = new AgentAdmitFilter(
            configWith(), client, r -> "write:payments",
            AgentAdmitFilter.Options.withOutcomeReporting());
        MockHttpServletResponse resp = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain() {
            @Override
            public void doFilter(jakarta.servlet.ServletRequest request,
                                 jakarta.servlet.ServletResponse response)
                    throws IOException {
                ((MockHttpServletResponse) response).setStatus(201);
                response.getWriter().write("{\"ok\":true}");
            }
        };

        filter.doFilter(agentRequest(), resp, chain);

        assertEquals(201, resp.getStatus());
        assertEquals("{\"ok\":true}", resp.getContentAsString());
        assertEquals(1, client.outcomeCalls);
    }
}
