package com.agentadmit;

import com.fasterxml.jackson.databind.ObjectMapper;
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
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Active-error fail-closed (SDK 1.10.0 semantic matrix §4/§6d-f): an
 * introspection response with {@code active: true} AND a string {@code error}
 * field is a DENIAL — HTTP 403, request handler NOT invoked — never a
 * pass-through. {@code insufficient_scope} maps to the step-up shape
 * ({@code error, required_scope, granted_scopes}); {@code bound_exceeded}
 * passes the hosted {@code error_description}/{@code bound}/{@code renewal}
 * fields through; any unknown code fails closed with a generic refusal.
 * Active responses WITHOUT an error field behave exactly as before (§5).
 */
class ActiveErrorDenialTest {

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
        return config;
    }

    /**
     * One-response stub. Overrides the telemetry-carrying send, which the
     * plain {@code sendIntrospectionRequest(String)} delegates to, so it
     * intercepts both the direct-verify and the filter path.
     */
    private static class OneResponseClient extends IntrospectionClient {
        private final HttpResponse<String> response;

        OneResponseClient(HttpResponse<String> response) {
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

    private static final String INSUFFICIENT_SCOPE_BODY =
        "{\"active\":true,\"user_id\":\"u1\",\"connection_id\":\"c1\","
            + "\"scopes\":[\"read:orders\"],\"error\":\"insufficient_scope\","
            + "\"error_description\":\"Scope not granted\","
            + "\"required_scope\":\"write:orders\",\"granted_scopes\":[\"read:orders\"]}";

    private static final String BOUND_EXCEEDED_BODY =
        "{\"active\":true,\"user_id\":\"u1\",\"connection_id\":\"c1\","
            + "\"scopes\":[\"pay:invoices\"],\"error\":\"bound_exceeded\","
            + "\"error_description\":\"Spending bound exceeded for this period.\","
            + "\"bound\":{\"type\":\"spend\",\"limit\":100,\"used\":100},"
            + "\"renewal\":\"2026-10-01T00:00:00Z\"}";

    private static final String UNKNOWN_ERROR_BODY =
        "{\"active\":true,\"user_id\":\"u1\",\"connection_id\":\"c1\","
            + "\"scopes\":[\"read:orders\"],\"error\":\"quota_exhausted\","
            + "\"error_description\":\"hosted-side detail\"}";

    // -------------------------------------------------------------------------
    // Client level: verify() refuses active+error responses with a 403 denial
    // -------------------------------------------------------------------------

    @Test
    void activeInsufficientScopeThrowsDenialWithStepUpShape() throws Exception {
        OneResponseClient client = new OneResponseClient(stubResponse(200, INSUFFICIENT_SCOPE_BODY));
        AgentAdmitException.ActiveErrorDenial ex = assertThrows(
            AgentAdmitException.ActiveErrorDenial.class, () -> client.verify("ag_at_dummy"));

        assertEquals(403, ex.getStatusCode());
        assertEquals("insufficient_scope", ex.getErrorCode());
        Map<String, Object> body = MAPPER.readValue(ex.getResponseBody(), Map.class);
        assertEquals("insufficient_scope", body.get("error"));
        assertEquals("write:orders", body.get("required_scope"));
        assertEquals(List.of("read:orders"), body.get("granted_scopes"));
    }

    @Test
    void insufficientScopePreservesLegacy403AndMessage() {
        // Pre-1.10 the client already special-cased insufficient_scope as a
        // 403 AgentAdmitException with the hosted error_description. The
        // generalized denial must keep that contract.
        OneResponseClient client = new OneResponseClient(stubResponse(200, INSUFFICIENT_SCOPE_BODY));
        AgentAdmitException ex = assertThrows(AgentAdmitException.class,
            () -> client.verify("ag_at_dummy"));
        assertEquals(403, ex.getStatusCode());
        assertEquals("Scope not granted", ex.getMessage());
    }

    @Test
    void insufficientScopeGrantedScopesFallBackToLocalScopes() throws Exception {
        // granted_scopes comes from the hosted response when present, the
        // response's own scopes list (local ctx) otherwise.
        String body = "{\"active\":true,\"user_id\":\"u1\",\"scopes\":[\"read:orders\"],"
            + "\"error\":\"insufficient_scope\",\"required_scope\":\"write:orders\"}";
        OneResponseClient client = new OneResponseClient(stubResponse(200, body));
        AgentAdmitException.ActiveErrorDenial ex = assertThrows(
            AgentAdmitException.ActiveErrorDenial.class, () -> client.verify("ag_at_dummy"));
        Map<String, Object> denial = MAPPER.readValue(ex.getResponseBody(), Map.class);
        assertEquals(List.of("read:orders"), denial.get("granted_scopes"));
    }

    @Test
    void insufficientScopeRequiredScopeFallsBackToDeclaredScopeUsed() throws Exception {
        // When the hosted response omits required_scope, the scope the caller
        // declared as scope_used identifies what was being enforced.
        String body = "{\"active\":true,\"user_id\":\"u1\",\"scopes\":[\"read:orders\"],"
            + "\"error\":\"insufficient_scope\"}";
        OneResponseClient client = new OneResponseClient(stubResponse(200, body));
        AgentAdmitException.ActiveErrorDenial ex = assertThrows(
            AgentAdmitException.ActiveErrorDenial.class,
            () -> client.verify("ag_at_dummy", VerifyTelemetry.of("write:orders", "/api/orders", "POST")));
        Map<String, Object> denial = MAPPER.readValue(ex.getResponseBody(), Map.class);
        assertEquals("write:orders", denial.get("required_scope"));
    }

    @Test
    void activeBoundExceededThrowsDenialPassingHostedFieldsThrough() throws Exception {
        OneResponseClient client = new OneResponseClient(stubResponse(200, BOUND_EXCEEDED_BODY));
        AgentAdmitException.ActiveErrorDenial ex = assertThrows(
            AgentAdmitException.ActiveErrorDenial.class, () -> client.verify("ag_at_dummy"));

        assertEquals(403, ex.getStatusCode());
        assertEquals("bound_exceeded", ex.getErrorCode());
        Map<String, Object> body = MAPPER.readValue(ex.getResponseBody(), Map.class);
        assertEquals("bound_exceeded", body.get("error"));
        assertEquals("Spending bound exceeded for this period.", body.get("error_description"));
        assertEquals(Map.of("type", "spend", "limit", 100, "used", 100), body.get("bound"));
        assertEquals("2026-10-01T00:00:00Z", body.get("renewal"));
    }

    @Test
    void unknownActiveErrorFailsClosedWithGenericDenial() throws Exception {
        // The forward-compatible v1.5.1 lesson: an error code this SDK has
        // never heard of still refuses the call.
        OneResponseClient client = new OneResponseClient(stubResponse(200, UNKNOWN_ERROR_BODY));
        AgentAdmitException.ActiveErrorDenial ex = assertThrows(
            AgentAdmitException.ActiveErrorDenial.class, () -> client.verify("ag_at_dummy"));

        assertEquals(403, ex.getStatusCode());
        assertEquals("quota_exhausted", ex.getErrorCode());
        Map<String, Object> body = MAPPER.readValue(ex.getResponseBody(), Map.class);
        assertEquals("quota_exhausted", body.get("error"));
        assertEquals("Call refused by the authorization service.", body.get("error_description"));
    }

    @Test
    void activeResponseWithoutErrorIsUnchanged() throws Exception {
        // §5: no behavior change for active responses without an error field.
        String body = "{\"active\":true,\"user_id\":\"u1\",\"connection_id\":\"c1\","
            + "\"scopes\":[\"read:orders\"],\"agent_label\":\"Bot\"}";
        OneResponseClient client = new OneResponseClient(stubResponse(200, body));
        IntrospectionClient.IntrospectionResult result = client.verify("ag_at_dummy");
        assertEquals("u1", result.userId());
        assertEquals(List.of("read:orders"), result.scopes());
    }

    @Test
    void inactiveResponseWithErrorRemains401() {
        // The denial applies to ACTIVE responses; inactive stays the existing
        // 401 invalid-token path.
        String body = "{\"active\":false,\"error\":\"connection_revoked\"}";
        OneResponseClient client = new OneResponseClient(stubResponse(200, body));
        AgentAdmitException ex = assertThrows(AgentAdmitException.class,
            () -> client.verify("ag_at_dummy"));
        assertEquals(401, ex.getStatusCode());
        assertFalse(ex instanceof AgentAdmitException.ActiveErrorDenial);
    }

    // -------------------------------------------------------------------------
    // Filter level: 403 written, handler chain NOT continued
    // -------------------------------------------------------------------------

    private static MockHttpServletRequest agentRequest() {
        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/api/orders");
        req.addHeader("Authorization", "Bearer ag_at_dummy_token");
        return req;
    }

    @Test
    void filterDeniesBoundExceededWith403AndDoesNotContinueChain() throws Exception {
        AgentAdmitFilter filter = new AgentAdmitFilter(
            configWith(), new OneResponseClient(stubResponse(200, BOUND_EXCEEDED_BODY)));
        MockHttpServletResponse resp = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(agentRequest(), resp, chain);

        assertNull(chain.getRequest(), "a refused call must NOT reach the handler");
        assertEquals(403, resp.getStatus());
        Map<String, Object> body = MAPPER.readValue(resp.getContentAsString(), Map.class);
        assertEquals("bound_exceeded", body.get("error"));
        assertEquals("Spending bound exceeded for this period.", body.get("error_description"));
        assertEquals(Map.of("type", "spend", "limit", 100, "used", 100), body.get("bound"));
        assertEquals("2026-10-01T00:00:00Z", body.get("renewal"));
    }

    @Test
    void filterDeniesInsufficientScopeWithStepUpShape() throws Exception {
        AgentAdmitFilter filter = new AgentAdmitFilter(
            configWith(), new OneResponseClient(stubResponse(200, INSUFFICIENT_SCOPE_BODY)));
        MockHttpServletResponse resp = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(agentRequest(), resp, chain);

        assertNull(chain.getRequest());
        assertEquals(403, resp.getStatus());
        Map<String, Object> body = MAPPER.readValue(resp.getContentAsString(), Map.class);
        assertEquals("insufficient_scope", body.get("error"));
        assertEquals("write:orders", body.get("required_scope"));
        assertEquals(List.of("read:orders"), body.get("granted_scopes"));
    }

    @Test
    void filterDeniesUnknownActiveErrorWith403() throws Exception {
        AgentAdmitFilter filter = new AgentAdmitFilter(
            configWith(), new OneResponseClient(stubResponse(200, UNKNOWN_ERROR_BODY)));
        MockHttpServletResponse resp = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(agentRequest(), resp, chain);

        assertNull(chain.getRequest(), "unknown refusal codes fail closed");
        assertEquals(403, resp.getStatus());
        Map<String, Object> body = MAPPER.readValue(resp.getContentAsString(), Map.class);
        assertEquals("quota_exhausted", body.get("error"));
        assertEquals("Call refused by the authorization service.", body.get("error_description"));
    }

    @Test
    void callerConsentFilterAlsoDeniesActiveErrorWith403() throws Exception {
        // The consent filter's external-agent path rides the same client, so
        // hosted refusals deny there too — fail closed everywhere.
        CallerConsentFilter filter = new CallerConsentFilter(
            configWith(),
            new OneResponseClient(stubResponse(200, BOUND_EXCEEDED_BODY)),
            new ConsentClient(configWith()),
            CallerConsentFilter.Options.defaults());
        MockHttpServletResponse resp = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(agentRequest(), resp, chain);

        assertNull(chain.getRequest());
        assertEquals(403, resp.getStatus());
        Map<String, Object> body = MAPPER.readValue(resp.getContentAsString(), Map.class);
        assertEquals("bound_exceeded", body.get("error"));
    }
}
