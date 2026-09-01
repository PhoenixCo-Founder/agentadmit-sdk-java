package com.agentadmit;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerExecutionChain;
import org.springframework.web.servlet.HandlerMapping;

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
 * Per-call audit telemetry on the verify request body (SDK 1.10.0 semantic
 * matrix §1/§2/§6a-c): the introspection POST body gains optional
 * {@code scope_used} (the single scope the route enforces, resolved BEFORE
 * introspection via {@link RequiredScopeResolver}), {@code endpoint} (request
 * path only — query string stripped, 500-char cap), and {@code method}
 * (uppercase, 20-char cap). Fields are sent whenever known and omitted when
 * not — never null or empty strings.
 */
class VerifyTelemetryTest {

    private static final String ACTIVE_BODY =
        "{\"active\":true,\"user_id\":\"user_1\",\"connection_id\":\"conn_1\","
            + "\"scopes\":[\"read:orders\"],\"agent_label\":\"Test Agent\"}";

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
     * Captures the EXACT verify request body the production path would send
     * (via the production {@code buildVerifyBody}), then answers with a stub
     * hosted response.
     */
    private static class CapturingClient extends IntrospectionClient {
        private final HttpResponse<String> response;
        Map<String, Object> lastBody;

        CapturingClient(HttpResponse<String> response) {
            super(configWith());
            this.response = response;
        }

        @Override
        @SuppressWarnings("unchecked")
        HttpResponse<String> sendIntrospectionRequest(String token, VerifyTelemetry telemetry)
                throws AgentAdmitException {
            try {
                lastBody = new ObjectMapper().readValue(buildVerifyBody(token, telemetry), Map.class);
            } catch (Exception e) {
                throw new AgentAdmitException("test body capture failed: " + e.getMessage(), 500);
            }
            return response;
        }

        @Override
        void sleepBeforeRetry(long ms) {
            // no-op in tests
        }
    }

    private static MockHttpServletRequest agentRequest(String method, String uri) {
        MockHttpServletRequest req = new MockHttpServletRequest(method, uri);
        req.addHeader("Authorization", "Bearer ag_at_dummy_token");
        return req;
    }

    // -------------------------------------------------------------------------
    // §6(a): the scope-enforcing path declares scope_used + endpoint + method
    // -------------------------------------------------------------------------

    @Test
    void verifyBodyCarriesScopeUsedEndpointAndMethodFromScopeEnforcingPath() throws Exception {
        CapturingClient client = new CapturingClient(stubResponse(200, ACTIVE_BODY));
        AgentAdmitFilter filter = new AgentAdmitFilter(configWith(), client, r -> "read:orders");
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(agentRequest("get", "/api/orders"), new MockHttpServletResponse(), chain);

        assertNotNull(chain.getRequest(), "valid token: chain continues");
        assertEquals("ag_at_dummy_token", client.lastBody.get("token"));
        assertEquals("read:orders", client.lastBody.get("scope_used"));
        assertEquals("/api/orders", client.lastBody.get("endpoint"));
        assertEquals("GET", client.lastBody.get("method"), "method is uppercased");
    }

    @Test
    void consentFirstTelemetryCarriesScopeWithoutChangingOrdinaryRequests() throws Exception {
        CapturingClient client = new CapturingClient(stubResponse(200, ACTIVE_BODY));
        MockHttpServletRequest req = agentRequest("GET", "/api/records");

        client.verify("ag_at_dummy_token",
            VerifyTelemetry.forConsentFirstRequest(req, "read:records"));

        assertEquals("read:records", client.lastBody.get("scope_used"));
        assertEquals("/api/records", client.lastBody.get("endpoint"));
        assertEquals("GET", client.lastBody.get("method"));
        assertEquals(true, client.lastBody.get("consent_first"));

        client.verify("ag_at_dummy_token", VerifyTelemetry.forRequest(req, "read:records"));
        assertFalse(client.lastBody.containsKey("consent_first"));
    }

    @Test
    void handlerMappingResolverReadsRequireScopeOffTheMappedHandler() throws Exception {
        // The full §2 restructure: the filter learns the scope the route
        // enforces (the @RequireScope the aspect will enforce later) BEFORE
        // introspection, via the MVC handler mapping.
        HandlerMapping mapping = request -> new HandlerExecutionChain(
            new HandlerMethod(new OrdersController(), OrdersController.class.getMethod("listOrders")));
        CapturingClient client = new CapturingClient(stubResponse(200, ACTIVE_BODY));
        AgentAdmitFilter filter = new AgentAdmitFilter(
            configWith(), client, new HandlerMappingScopeResolver(() -> mapping));

        filter.doFilter(agentRequest("GET", "/api/orders"),
            new MockHttpServletResponse(), new MockFilterChain());

        assertEquals("read:orders", client.lastBody.get("scope_used"));
    }

    @Test
    void handlerMappingResolverReadsRequireScopeIfAgent() throws Exception {
        HandlerMapping mapping = request -> new HandlerExecutionChain(
            new HandlerMethod(new OrdersController(), OrdersController.class.getMethod("profile")));
        HandlerMappingScopeResolver resolver = new HandlerMappingScopeResolver(() -> mapping);

        assertEquals("read:profile",
            resolver.resolveRequiredScope(agentRequest("GET", "/api/profile")));
    }

    @Test
    void handlerMappingResolverResolvesNullSafely() throws Exception {
        // Unannotated handler, absent mapping, and a throwing mapping all
        // resolve null — telemetry never blocks verification.
        HandlerMapping unannotated = request -> new HandlerExecutionChain(
            new HandlerMethod(new OrdersController(), OrdersController.class.getMethod("unannotated")));
        assertNull(new HandlerMappingScopeResolver(() -> unannotated)
            .resolveRequiredScope(agentRequest("GET", "/api/misc")));
        assertNull(new HandlerMappingScopeResolver(() -> null)
            .resolveRequiredScope(agentRequest("GET", "/api/misc")));
        HandlerMapping throwing = request -> { throw new IllegalStateException("boom"); };
        assertNull(new HandlerMappingScopeResolver(() -> throwing)
            .resolveRequiredScope(agentRequest("GET", "/api/misc")));
    }

    @Test
    void throwingScopeResolverDoesNotBlockVerification() throws Exception {
        CapturingClient client = new CapturingClient(stubResponse(200, ACTIVE_BODY));
        AgentAdmitFilter filter = new AgentAdmitFilter(configWith(), client,
            r -> { throw new IllegalStateException("resolver boom"); });
        MockHttpServletRequest req = agentRequest("GET", "/api/orders");
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(req, new MockHttpServletResponse(), chain);

        assertNotNull(chain.getRequest(), "verification proceeds without scope_used");
        assertFalse(client.lastBody.containsKey("scope_used"));
        assertEquals("/api/orders", client.lastBody.get("endpoint"));
        assertEquals("agent", req.getAttribute("agentadmit.authType"));
    }

    // -------------------------------------------------------------------------
    // §6(b): scope_used omitted when unknown; endpoint + method still sent
    // -------------------------------------------------------------------------

    @Test
    void verifyBodyOmitsScopeUsedWhenUnknownButStillSendsEndpointAndMethod() throws Exception {
        CapturingClient client = new CapturingClient(stubResponse(200, ACTIVE_BODY));
        // Two-arg constructor: no scope resolver configured.
        AgentAdmitFilter filter = new AgentAdmitFilter(configWith(), client);
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(agentRequest("POST", "/api/orders"), new MockHttpServletResponse(), chain);

        assertNotNull(chain.getRequest());
        assertFalse(client.lastBody.containsKey("scope_used"),
            "unknown scope must be omitted, never null/empty");
        assertEquals("/api/orders", client.lastBody.get("endpoint"));
        assertEquals("POST", client.lastBody.get("method"));
    }

    @Test
    void verifyWithoutTelemetrySendsTokenOnly() throws Exception {
        // Direct client-library verify with no request context: body is
        // exactly {token}, same as pre-1.10.
        CapturingClient client = new CapturingClient(stubResponse(200, ACTIVE_BODY));
        client.verify("ag_at_dummy_token");
        assertEquals(Map.of("token", "ag_at_dummy_token"), client.lastBody);
    }

    // -------------------------------------------------------------------------
    // §6(c): query-string strip + 500-char endpoint truncation
    // -------------------------------------------------------------------------

    @Test
    void endpointQueryStringIsStripped() throws Exception {
        CapturingClient client = new CapturingClient(stubResponse(200, ACTIVE_BODY));
        AgentAdmitFilter filter = new AgentAdmitFilter(configWith(), client, r -> "read:orders");

        filter.doFilter(agentRequest("GET", "/api/orders?user=42&ssn=000-secret"),
            new MockHttpServletResponse(), new MockFilterChain());

        assertEquals("/api/orders", client.lastBody.get("endpoint"),
            "query strings can carry PII and must never leave the app");
        assertFalse(client.lastBody.toString().contains("secret"));
    }

    @Test
    void endpointIsTruncatedTo500Chars() throws Exception {
        String longPath = "/api/" + "x".repeat(600);
        CapturingClient client = new CapturingClient(stubResponse(200, ACTIVE_BODY));
        AgentAdmitFilter filter = new AgentAdmitFilter(configWith(), client);

        filter.doFilter(agentRequest("GET", longPath + "?q=1"),
            new MockHttpServletResponse(), new MockFilterChain());

        String endpoint = (String) client.lastBody.get("endpoint");
        assertEquals(500, endpoint.length());
        assertEquals(longPath.substring(0, 500), endpoint);
    }

    @Test
    void telemetryRecordNormalizesAtConstruction() {
        // Query + fragment strip, uppercase method, and length caps happen in
        // the record itself so no un-normalized instance can exist.
        VerifyTelemetry t = new VerifyTelemetry("read:orders", "/a/b?x=1#frag", "patch");
        assertEquals("/a/b", t.endpoint());
        assertEquals("PATCH", t.method());
        assertEquals("read:orders", t.scopeUsed());

        assertEquals(120, VerifyTelemetry.of("s".repeat(200), null, null).scopeUsed().length());
        assertEquals(20, VerifyTelemetry.of(null, null, "m".repeat(30)).method().length());
        assertEquals(500, VerifyTelemetry.of(null, "/" + "p".repeat(600), null).endpoint().length());
    }

    @Test
    void telemetryRecordCollapsesBlankAndQueryOnlyValuesToNull() {
        VerifyTelemetry t = VerifyTelemetry.of("  ", "?only=query", "");
        assertNull(t.scopeUsed(), "blank scope collapses to null (omitted, never empty-string)");
        assertNull(t.endpoint(), "query-only endpoint collapses to null");
        assertNull(t.method());
    }

    /** Dummy controller carrying the annotations the aspect enforces. */
    static class OrdersController {
        @RequireScope("read:orders")
        public String listOrders() { return "ok"; }

        @RequireScopeIfAgent("read:profile")
        public String profile() { return "ok"; }

        public String unannotated() { return "ok"; }
    }
}
