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
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * CallerConsentFilter tests: classify the caller from credential structure
 * before any consent check; route each class to its OWN isolated path; fail
 * closed on a denied verdict or an unreachable ledger; and never let one
 * class inherit another's decision.
 *
 * <p>On the external-agent path the consent verdict is evaluated BEFORE the
 * scope check (Patent FIG. 3 stage order), so a denied class never learns
 * scope state; an absent or malformed inline verdict is resolved through the
 * Consent Ledger, fail closed — absence is never a grant.
 */
class CallerConsentFilterTest {

    /** Modern hosted response: the consent verdict rides inline. */
    private static final String ACTIVE_BODY =
        "{\"active\":true,\"user_id\":\"user_1\",\"connection_id\":\"conn_1\","
            + "\"scopes\":[\"read:things\"],\"agent_label\":\"Test Agent\","
            + "\"consent\":{\"caller_class\":\"external_agent\",\"granted\":true,\"source\":\"setting\"}}";

    /**
     * Degraded-mode hosted response: the service omits the consent block when
     * its consent-store read fails. Absence is never a grant — the filter must
     * resolve the verdict through the Consent Ledger instead.
     */
    private static final String NO_VERDICT_BODY =
        "{\"active\":true,\"user_id\":\"user_1\",\"connection_id\":\"conn_1\","
            + "\"scopes\":[\"read:things\"],\"agent_label\":\"Test Agent\"}";

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
        HttpResponse<String> sendIntrospectionRequest(String token) {
            return response;
        }

        @Override
        void sleepBeforeRetry(long ms) {
            // no-op in tests
        }
    }

    private static class OneResponseConsentClient extends ConsentClient {
        private final HttpResponse<String> response;
        final AtomicInteger calls = new AtomicInteger();

        OneResponseConsentClient(HttpResponse<String> response) {
            super(configWith());
            this.response = response;
        }

        @Override
        HttpResponse<String> sendConsentRequest(HttpRequest request) throws Exception {
            calls.incrementAndGet();
            if (response == null) {
                throw new RuntimeException("ledger unreachable");
            }
            return response;
        }
    }

    /**
     * Records checkConsent arguments so tests can assert the external-agent
     * ledger fallback asks for the right caller class and owner.
     */
    private static class RecordingConsentClient extends ConsentClient {
        final AtomicInteger calls = new AtomicInteger();
        volatile String lastAppUserId;
        volatile String lastCallerClass;
        volatile String lastScopeGroup;
        private final Map<String, Object> verdict;
        private final boolean throwOnCall;

        RecordingConsentClient(Map<String, Object> verdict, boolean throwOnCall) {
            super(configWith());
            this.verdict = verdict;
            this.throwOnCall = throwOnCall;
        }

        @Override
        public Map<String, Object> checkConsent(String appUserId, String callerClass, String scopeGroup)
                throws AgentAdmitException {
            calls.incrementAndGet();
            lastAppUserId = appUserId;
            lastCallerClass = callerClass;
            lastScopeGroup = scopeGroup;
            if (throwOnCall) {
                throw new AgentAdmitException("ledger unreachable", 502);
            }
            return verdict;
        }
    }

    private static CallerConsentFilter filterWithLedger(
            HttpResponse<String> verifyResponse,
            RecordingConsentClient ledger,
            CallerConsentFilter.Options options) {
        return new CallerConsentFilter(
            configWith(),
            new OneResponseIntrospectionClient(verifyResponse),
            ledger,
            options);
    }

    private static CallerConsentFilter filter(
            HttpResponse<String> verifyResponse,
            HttpResponse<String> consentResponse,
            CallerConsentFilter.Options options) {
        return new CallerConsentFilter(
            configWith(),
            new OneResponseIntrospectionClient(verifyResponse),
            new OneResponseConsentClient(consentResponse),
            options);
    }

    private static MockHttpServletRequest agentRequest() {
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.addHeader("Authorization", "Bearer ag_at_dummy_token");
        return req;
    }

    private static MockHttpServletRequest humanRequest() {
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.addHeader("Authorization", "Bearer session_jwt");
        return req;
    }

    // --- classifyCaller ----------------------------------------------------

    @Test
    void classifiesAgentTokenAsExternalAgent() {
        CallerConsentFilter f = filter(null, null, CallerConsentFilter.Options.defaults());
        assertEquals("external_agent", f.classifyCaller(agentRequest()));
    }

    @Test
    void classifiesNonAgentAsHumanByDefault() {
        CallerConsentFilter f = filter(null, null, CallerConsentFilter.Options.defaults());
        assertEquals("human_session", f.classifyCaller(humanRequest()));
    }

    @Test
    void honorsNonAgentClassifierForInAppAi() {
        CallerConsentFilter.Options opts = new CallerConsentFilter.Options(
            null,
            r -> "secret".equals(r.getHeader("x-internal-ai")) ? "in_app_ai" : "human_session",
            null, null, false);
        CallerConsentFilter f = filter(null, null, opts);
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.addHeader("x-internal-ai", "secret");
        assertEquals("in_app_ai", f.classifyCaller(req));
    }

    // --- external_agent path -------------------------------------------------

    @Test
    void externalAgentAllowsWithRequiredScope() throws Exception {
        CallerConsentFilter.Options opts = new CallerConsentFilter.Options(null, null, "read:things", null, false);
        CallerConsentFilter f = filter(stubResponse(200, ACTIVE_BODY), null, opts);
        MockHttpServletRequest req = agentRequest();
        MockHttpServletResponse resp = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        f.doFilter(req, resp, chain);

        assertNotNull(chain.getRequest(), "chain should continue");
        assertEquals("agent", req.getAttribute("agentadmit.authType"));
        assertEquals("external_agent", req.getAttribute("agentadmit.callerClass"));
    }

    @Test
    void externalAgentDeniedOnMissingScope() throws Exception {
        CallerConsentFilter.Options opts = new CallerConsentFilter.Options(null, null, "write:things", null, false);
        CallerConsentFilter f = filter(stubResponse(200, ACTIVE_BODY), null, opts);
        MockHttpServletResponse resp = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        f.doFilter(agentRequest(), resp, chain);

        assertNull(chain.getRequest(), "chain must not continue");
        assertEquals(403, resp.getStatus());
        assertTrue(resp.getContentAsString().contains("insufficient_scope"));
    }

    @Test
    void externalAgentDeniedWhenConsentDenied() throws Exception {
        String body = "{\"active\":true,\"user_id\":\"user_1\",\"connection_id\":\"conn_1\","
            + "\"scopes\":[\"read:things\"],\"consent\":{\"caller_class\":\"external_agent\","
            + "\"granted\":false,\"source\":\"setting\"}}";
        CallerConsentFilter f = filter(stubResponse(200, body), null, CallerConsentFilter.Options.defaults());
        MockHttpServletResponse resp = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        f.doFilter(agentRequest(), resp, chain);

        assertNull(chain.getRequest());
        assertEquals(403, resp.getStatus());
        assertTrue(resp.getContentAsString().contains("consent_not_granted"));
    }

    @Test
    void externalAgentConsentPrecedesScopeAndLeaksNoScopeState() throws Exception {
        // Denied verdict AND missing required scope: the caller gets ONLY the
        // consent denial (Patent FIG. 3 stage order). Scope state and step-up
        // guidance must never reach a class the owner has denied.
        String body = "{\"active\":true,\"user_id\":\"user_1\",\"connection_id\":\"conn_1\","
            + "\"scopes\":[\"read:things\"],\"consent\":{\"caller_class\":\"external_agent\","
            + "\"granted\":false,\"source\":\"setting\"}}";
        CallerConsentFilter.Options opts = new CallerConsentFilter.Options(null, null, "write:things", null, false);
        CallerConsentFilter f = filter(stubResponse(200, body), null, opts);
        MockHttpServletResponse resp = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        f.doFilter(agentRequest(), resp, chain);

        assertNull(chain.getRequest());
        assertEquals(403, resp.getStatus());
        String content = resp.getContentAsString();
        assertTrue(content.contains("consent_not_granted"));
        assertFalse(content.contains("insufficient_scope"), "must not reveal scope state");
        assertFalse(content.contains("granted_scopes"), "must not reveal granted scopes");
        assertFalse(content.contains("write:things"), "must not reveal step-up guidance");
    }

    @Test
    void externalAgentAbsentVerdictResolvedThroughLedgerAllow() throws Exception {
        RecordingConsentClient ledger = new RecordingConsentClient(
            Map.of("caller_class", "external_agent", "granted", Boolean.TRUE, "source", "setting"), false);
        CallerConsentFilter f = filterWithLedger(
            stubResponse(200, NO_VERDICT_BODY), ledger, CallerConsentFilter.Options.defaults());
        MockHttpServletRequest req = agentRequest();
        MockFilterChain chain = new MockFilterChain();

        f.doFilter(req, new MockHttpServletResponse(), chain);

        assertNotNull(chain.getRequest(), "ledger grant lets the chain continue");
        assertEquals(1, ledger.calls.get(), "absent verdict must be resolved through the ledger");
        assertEquals("external_agent", ledger.lastCallerClass);
        assertEquals("user_1", ledger.lastAppUserId, "owner comes from the introspection result");
        @SuppressWarnings("unchecked")
        Map<String, Object> resolved = (Map<String, Object>) req.getAttribute("agentadmit.consent");
        assertEquals(Boolean.TRUE, resolved.get("granted"), "resolved verdict lands on agentadmit.consent");
    }

    @Test
    void externalAgentAbsentVerdictLedgerDenyIs403() throws Exception {
        RecordingConsentClient ledger = new RecordingConsentClient(
            Map.of("caller_class", "external_agent", "granted", Boolean.FALSE, "source", "setting"), false);
        CallerConsentFilter f = filterWithLedger(
            stubResponse(200, NO_VERDICT_BODY), ledger, CallerConsentFilter.Options.defaults());
        MockHttpServletResponse resp = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        f.doFilter(agentRequest(), resp, chain);

        assertNull(chain.getRequest());
        assertEquals(1, ledger.calls.get());
        assertEquals(403, resp.getStatus());
        assertTrue(resp.getContentAsString().contains("consent_not_granted"));
    }

    @Test
    void externalAgentAbsentVerdictLedgerErrorFailsClosed503() throws Exception {
        RecordingConsentClient ledger = new RecordingConsentClient(null, true);
        CallerConsentFilter f = filterWithLedger(
            stubResponse(200, NO_VERDICT_BODY), ledger, CallerConsentFilter.Options.defaults());
        MockHttpServletResponse resp = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        f.doFilter(agentRequest(), resp, chain);

        assertNull(chain.getRequest(), "an erroring ledger must never allow");
        assertEquals(503, resp.getStatus());
        assertTrue(resp.getContentAsString().contains("consent_unavailable"));
    }

    @Test
    void externalAgentMalformedVerdictResolvedThroughLedger() throws Exception {
        // granted:"true" (a string, not a boolean) is malformed — never a
        // grant; the filter resolves it through the ledger like absence.
        String body = "{\"active\":true,\"user_id\":\"user_1\",\"connection_id\":\"conn_1\","
            + "\"scopes\":[\"read:things\"],\"consent\":{\"caller_class\":\"external_agent\","
            + "\"granted\":\"true\",\"source\":\"setting\"}}";
        RecordingConsentClient ledger = new RecordingConsentClient(
            Map.of("caller_class", "external_agent", "granted", Boolean.FALSE, "source", "setting"), false);
        CallerConsentFilter f = filterWithLedger(
            stubResponse(200, body), ledger, CallerConsentFilter.Options.defaults());
        MockHttpServletResponse resp = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        f.doFilter(agentRequest(), resp, chain);

        assertNull(chain.getRequest());
        assertEquals(1, ledger.calls.get(), "malformed verdict must be resolved through the ledger");
        assertEquals("external_agent", ledger.lastCallerClass);
        assertEquals(403, resp.getStatus());
        assertTrue(resp.getContentAsString().contains("consent_not_granted"));
    }

    @Test
    void externalAgentAbsentVerdictNoResolvableOwnerFailsClosed503() throws Exception {
        // verify() lets an empty user_id through; with no consent block and no
        // resolvable owner the filter cannot ask the ledger — fail closed.
        String body = "{\"active\":true,\"user_id\":\"\",\"connection_id\":\"conn_1\","
            + "\"scopes\":[\"read:things\"]}";
        RecordingConsentClient ledger = new RecordingConsentClient(
            Map.of("granted", Boolean.TRUE), false);
        CallerConsentFilter f = filterWithLedger(
            stubResponse(200, body), ledger, CallerConsentFilter.Options.defaults());
        MockHttpServletResponse resp = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        f.doFilter(agentRequest(), resp, chain);

        assertNull(chain.getRequest());
        assertEquals(0, ledger.calls.get(), "no owner to ask the ledger about");
        assertEquals(503, resp.getStatus());
        assertTrue(resp.getContentAsString().contains("consent_unavailable"));
    }

    @Test
    void externalAgentLedgerFallbackPassesScopeGroup() throws Exception {
        RecordingConsentClient ledger = new RecordingConsentClient(
            Map.of("granted", Boolean.TRUE), false);
        CallerConsentFilter.Options opts = new CallerConsentFilter.Options(
            null, null, null, "billing", false);
        CallerConsentFilter f = filterWithLedger(stubResponse(200, NO_VERDICT_BODY), ledger, opts);
        MockFilterChain chain = new MockFilterChain();

        f.doFilter(agentRequest(), new MockHttpServletResponse(), chain);

        assertNotNull(chain.getRequest());
        assertEquals("billing", ledger.lastScopeGroup);
    }

    @Test
    void externalAgentRejectedOnInvalidToken() throws Exception {
        String body = "{\"active\":false,\"error\":\"invalid_token\"}";
        CallerConsentFilter f = filter(stubResponse(200, body), null, CallerConsentFilter.Options.defaults());
        MockHttpServletResponse resp = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        f.doFilter(agentRequest(), resp, chain);

        assertNull(chain.getRequest());
        assertEquals(401, resp.getStatus());
    }

    // --- in_app_ai path ------------------------------------------------------

    private static CallerConsentFilter.Options internalAiOptions() {
        return new CallerConsentFilter.Options(
            r -> "user_8842",
            r -> "in_app_ai",
            null, null, false);
    }

    @Test
    void inAppAiAllowsWhenGranted() throws Exception {
        String verdict = "{\"caller_class\":\"in_app_ai\",\"granted\":true,\"source\":\"setting\"}";
        CallerConsentFilter f = filter(null, stubResponse(200, verdict), internalAiOptions());
        MockHttpServletRequest req = new MockHttpServletRequest();
        MockFilterChain chain = new MockFilterChain();

        f.doFilter(req, new MockHttpServletResponse(), chain);

        assertNotNull(chain.getRequest());
        assertEquals("in_app_ai", req.getAttribute("agentadmit.authType"));
    }

    @Test
    void inAppAiDeniedWhenDenied() throws Exception {
        String verdict = "{\"caller_class\":\"in_app_ai\",\"granted\":false,\"source\":\"setting\"}";
        CallerConsentFilter f = filter(null, stubResponse(200, verdict), internalAiOptions());
        MockHttpServletResponse resp = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        f.doFilter(new MockHttpServletRequest(), resp, chain);

        assertNull(chain.getRequest());
        assertEquals(403, resp.getStatus());
        assertTrue(resp.getContentAsString().contains("consent_not_granted"));
    }

    @Test
    void inAppAiFailsClosedWhenLedgerUnreachable() throws Exception {
        CallerConsentFilter f = filter(null, null, internalAiOptions()); // null consent response -> throws
        MockHttpServletResponse resp = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        f.doFilter(new MockHttpServletRequest(), resp, chain);

        assertNull(chain.getRequest());
        assertEquals(503, resp.getStatus());
        assertTrue(resp.getContentAsString().contains("consent_unavailable"));
    }

    @Test
    void inAppAiRequiresOwnerResolver() throws Exception {
        CallerConsentFilter.Options opts = new CallerConsentFilter.Options(
            null, r -> "in_app_ai", null, null, false);
        CallerConsentFilter f = filter(null, null, opts);
        MockHttpServletResponse resp = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        f.doFilter(new MockHttpServletRequest(), resp, chain);

        assertNull(chain.getRequest());
        assertEquals(500, resp.getStatus());
    }

    // --- human_session path ----------------------------------------------------

    @Test
    void humanDefersWithoutLedgerCall() throws Exception {
        OneResponseConsentClient consentClient = new OneResponseConsentClient(null);
        CallerConsentFilter f = new CallerConsentFilter(
            configWith(),
            new OneResponseIntrospectionClient(null),
            consentClient,
            CallerConsentFilter.Options.defaults());
        MockHttpServletRequest req = humanRequest();
        MockFilterChain chain = new MockFilterChain();

        f.doFilter(req, new MockHttpServletResponse(), chain);

        assertNotNull(chain.getRequest(), "human path must continue by default");
        assertEquals("human_session", req.getAttribute("agentadmit.callerClass"));
        assertEquals("user", req.getAttribute("agentadmit.authType"));
        assertEquals(0, consentClient.calls.get(), "Branch A is the app's own model; no ledger call");
    }

    @Test
    void humanGatedWhenGateHumanSet() throws Exception {
        String verdict = "{\"caller_class\":\"human_session\",\"granted\":false,\"source\":\"setting\"}";
        CallerConsentFilter.Options opts = new CallerConsentFilter.Options(
            r -> "user_1", null, null, null, true);
        CallerConsentFilter f = filter(null, stubResponse(200, verdict), opts);
        MockHttpServletResponse resp = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        f.doFilter(humanRequest(), resp, chain);

        assertNull(chain.getRequest());
        assertEquals(403, resp.getStatus());
        assertTrue(resp.getContentAsString().contains("consent_not_granted"));
    }
}
