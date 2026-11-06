package com.agentadmit;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import javax.net.ssl.SSLSession;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for agent designation (1.14.0).
 *
 * The hosted /verify response carries what the USER said a connection is for
 * (designated_agent) and what the AGENT reported about itself
 * (agent_reported). IntrospectionClient.verify must surface both on the
 * result and the filter must set them as request attributes. Review-time
 * records only: a malformed block reads as null and never fails the verify.
 */
class AgentDesignationTest {

    private static final String BASE =
        "\"active\":true,\"user_id\":\"u1\",\"connection_id\":\"conn1\","
            + "\"scopes\":[\"read:orders\"],\"agent_label\":\"my-agent\"";

    private static final String LISTED =
        "{\"agent_id\":\"agt_openclaw\",\"name\":\"OpenClaw\",\"source\":\"user_declared\","
            + "\"model\":{\"model_id\":\"mdl_claude\",\"name\":\"Claude (Anthropic)\"}}";

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

    private static class OneResponseIntrospectionClient extends IntrospectionClient {
        private final HttpResponse<String> response;

        OneResponseIntrospectionClient(HttpResponse<String> response) {
            super(configWith());
            this.response = response;
        }

        @Override
        HttpResponse<String> sendIntrospectionRequest(String token, VerifyTelemetry telemetry) {
            return response;
        }

        @Override
        void sleepBeforeRetry(long ms) {
            // no-op in tests
        }
    }

    private static IntrospectionClient.IntrospectionResult verifyWith(String extraFields) throws Exception {
        String body = "{" + BASE + (extraFields.isEmpty() ? "" : "," + extraFields) + "}";
        return new OneResponseIntrospectionClient(stubResponse(200, body)).verify("ag_at_dummy");
    }

    // -------------------------------------------------------------------------
    // verify pass-through
    // -------------------------------------------------------------------------

    @Test
    void userDesignationReachesTheResult() throws Exception {
        IntrospectionClient.IntrospectionResult result = verifyWith("\"designated_agent\":" + LISTED);
        assertEquals(
            new DesignatedAgent("agt_openclaw", "OpenClaw", "user_declared",
                new DesignatedAgent.Model("mdl_claude", "Claude (Anthropic)")),
            result.designatedAgent());
    }

    @Test
    void agentLabelStaysSeparateFromTheDesignation() throws Exception {
        IntrospectionClient.IntrospectionResult result = verifyWith("\"designated_agent\":" + LISTED);
        assertEquals("my-agent", result.agentLabel());
        assertEquals("OpenClaw", result.designatedAgent().name());
    }

    @Test
    void typedNameHasNullAgentIdAndNoModelIsNull() throws Exception {
        IntrospectionClient.IntrospectionResult result = verifyWith(
            "\"designated_agent\":{\"agent_id\":null,\"name\":\"My Home Agent\","
                + "\"source\":\"user_declared\",\"model\":null}");
        assertNull(result.designatedAgent().agentId());
        assertEquals("My Home Agent", result.designatedAgent().name());
        assertNull(result.designatedAgent().model());
    }

    @Test
    void wireNullIsNoDesignation() throws Exception {
        IntrospectionClient.IntrospectionResult result =
            verifyWith("\"designated_agent\":null,\"agent_reported\":null");
        assertNull(result.designatedAgent());
        assertNull(result.agentReported());
    }

    @Test
    void absentFieldsAreNullForOlderServers() throws Exception {
        IntrospectionClient.IntrospectionResult result = verifyWith("");
        assertNull(result.designatedAgent());
        assertNull(result.agentReported());
    }

    @Test
    void agentReportedReachesTheResult() throws Exception {
        IntrospectionClient.IntrospectionResult result = verifyWith(
            "\"agent_reported\":{\"platform\":\"openclaw\","
                + "\"model\":{\"id\":\"claude-fable-5-1\",\"version\":\"2026-09\"}}");
        assertEquals(
            new AgentReported("openclaw", new AgentReported.Model("claude-fable-5-1", "2026-09")),
            result.agentReported());
    }

    @Test
    void bothRecordsAreCarriedIndependently() throws Exception {
        IntrospectionClient.IntrospectionResult result = verifyWith(
            "\"designated_agent\":" + LISTED
                + ",\"agent_reported\":{\"platform\":\"other-runtime\",\"model\":{\"id\":\"gpt-6\"}}");
        assertEquals("OpenClaw", result.designatedAgent().name());
        assertEquals("other-runtime", result.agentReported().platform());
        assertEquals(new AgentReported.Model("gpt-6", null), result.agentReported().model());
    }

    @Test
    void malformedDesignationIsDroppedAndNeverFailsTheCall() throws Exception {
        List<String> bad = List.of(
            "\"OpenClaw\"",
            "[\"OpenClaw\"]",
            "42",
            "{\"name\":\"OpenClaw\"}",
            "{\"name\":\"OpenClaw\",\"source\":\"verified\"}",
            "{\"name\":\"\",\"source\":\"user_declared\"}",
            "{\"name\":7,\"source\":\"user_declared\"}");
        for (String value : bad) {
            IntrospectionClient.IntrospectionResult result =
                verifyWith("\"designated_agent\":" + value + ",\"agent_reported\":\"x\"");
            assertNull(result.designatedAgent(), value + " should be dropped");
            assertNull(result.agentReported());
            assertEquals("u1", result.userId());
            assertEquals(List.of("read:orders"), result.scopes());
        }
    }

    // -------------------------------------------------------------------------
    // readers
    // -------------------------------------------------------------------------

    @Test
    void malformedModelIsDroppedAndTheAppIsKept() {
        List<Object> bad = Arrays.asList(
            "Claude", Map.of("model_id", "mdl_1"), Map.of("name", ""), Map.of("name", 5), List.of());
        for (Object model : bad) {
            DesignatedAgent out = DesignatedAgent.fromVerifyData(Map.of(
                "agent_id", "agt_1", "name", "OpenClaw", "source", "user_declared", "model", model));
            assertEquals("OpenClaw", out.name());
            assertNull(out.model(), model + " should be dropped");
        }
    }

    @Test
    void modelNamedWithoutAListedIdHasNullModelId() {
        DesignatedAgent out = DesignatedAgent.fromVerifyData(Map.of(
            "name", "OpenClaw", "source", "user_declared",
            "model", Map.of("model_id", 9, "name", "A local model")));
        assertNull(out.agentId());
        assertEquals(new DesignatedAgent.Model(null, "A local model"), out.model());
    }

    @Test
    void designationReaderReturnsNullForAnythingElse() {
        List<Object> bad = Arrays.asList(
            null, "x", 1, List.of(), Map.of(), Map.of("name", "A"),
            Map.of("name", "A", "source", "operator_verified"), Map.of("source", "user_declared"));
        for (Object value : bad) {
            assertNull(DesignatedAgent.fromVerifyData(value), value + " should be null");
        }
    }

    @Test
    void agentReportedPlatformOnlyModelOnlyAndNonStringVersion() {
        assertEquals(new AgentReported("openclaw", null),
            AgentReported.fromVerifyData(Map.of("platform", "openclaw")));
        assertEquals(new AgentReported(null, new AgentReported.Model("m", null)),
            AgentReported.fromVerifyData(Map.of("model", Map.of("id", "m"))));
        assertEquals(new AgentReported(null, new AgentReported.Model("m", null)),
            AgentReported.fromVerifyData(Map.of("platform", 3, "model", Map.of("id", "m", "version", 5.1))));
    }

    @Test
    void agentReportedReaderReturnsNullWithNeitherPlatformNorModelId() {
        List<Object> bad = Arrays.asList(
            null, "x", List.of(), Map.of(), Map.of("platform", ""), Map.of("model", Map.of()),
            Map.of("model", Map.of("version", "1")), Map.of("model", Map.of("id", "")));
        for (Object value : bad) {
            assertNull(AgentReported.fromVerifyData(value), value + " should be null");
        }
    }

    @Test
    void olderConstructorsLeaveBothFieldsNull() {
        IntrospectionClient.IntrospectionResult result = new IntrospectionClient.IntrospectionResult(
            "u1", "conn1", List.of("read:orders"), "my-agent", null, null, null, null, 0L,
            null, null, null, null, null, "audit_1");
        assertNull(result.designatedAgent());
        assertNull(result.agentReported());
        assertEquals("audit_1", result.auditRowId());
    }

    // -------------------------------------------------------------------------
    // filter attributes
    // -------------------------------------------------------------------------

    private static MockHttpServletRequest runFilter(String extraFields) throws Exception {
        String body = "{" + BASE + (extraFields.isEmpty() ? "" : "," + extraFields) + "}";
        AgentAdmitFilter filter = new AgentAdmitFilter(
            configWith(), new OneResponseIntrospectionClient(stubResponse(200, body)), r -> "read:orders");
        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/api/orders");
        req.addHeader("Authorization", "Bearer ag_at_dummy_token");
        MockHttpServletResponse resp = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(req, resp, chain);
        assertNotNull(chain.getRequest(), "chain should continue");
        return req;
    }

    @Test
    void filterSetsBothAttributesWhenPresent() throws Exception {
        MockHttpServletRequest req = runFilter(
            "\"designated_agent\":" + LISTED + ",\"agent_reported\":{\"platform\":\"openclaw\"}");
        DesignatedAgent named = (DesignatedAgent) req.getAttribute("agentadmit.designatedAgent");
        assertEquals("OpenClaw", named.name());
        assertEquals("Claude (Anthropic)", named.model().name());
        assertEquals(new AgentReported("openclaw", null), req.getAttribute("agentadmit.agentReported"));
        assertEquals("my-agent", req.getAttribute("agentadmit.agentLabel"));
    }

    @Test
    void filterLeavesAttributesUnsetWhenAbsentOrMalformed() throws Exception {
        MockHttpServletRequest req = runFilter("\"designated_agent\":{\"name\":\"OpenClaw\"}");
        assertNull(req.getAttribute("agentadmit.designatedAgent"));
        assertNull(req.getAttribute("agentadmit.agentReported"));
    }
}
