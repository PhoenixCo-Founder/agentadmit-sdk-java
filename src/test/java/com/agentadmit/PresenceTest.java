package com.agentadmit;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.aspectj.lang.ProceedingJoinPoint;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.net.ssl.SSLSession;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Proxy;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the presence block (WebAuthn human-presence step-up, server
 * Phase 2). IntrospectionClient.verify must:
 *   - attach presence when the platform returns a well-formed block
 *   - leave it null when absent (older servers) or malformed (strictness
 *     mirrors the active flag: verified must be strictly boolean)
 *
 * isPresenceVerified() must be strict and fail closed: only a present block
 * with verified Boolean.TRUE counts. This matches consentGranted(), which
 * also fails closed — an absent or malformed verdict is never a grant.
 *
 * The @RequirePresence guard must return 401 without an agent token
 * (mirroring @RequireScope) and 403 presence_required when the connection
 * was minted without a completed ceremony.
 */
class PresenceTest {

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

    // -------------------------------------------------------------------------
    // Presence parsing end to end through IntrospectionClient.verify
    // -------------------------------------------------------------------------

    private static IntrospectionClient.IntrospectionResult verifyWithBody(String body) throws Exception {
        OneResponseIntrospectionClient client =
            new OneResponseIntrospectionClient(stubResponse(200, body));
        return client.verify("ag_at_dummy");
    }

    private static String verifyBodyWithPresence(String presenceJson) {
        String base = "{\"active\":true,\"user_id\":\"u1\",\"connection_id\":\"conn1\","
            + "\"scopes\":[\"read:orders\"],\"agent_label\":\"Bot\"";
        return presenceJson == null ? base + "}" : base + ",\"presence\":" + presenceJson + "}";
    }

    @Test
    void verifiedPresenceBlockParses() throws Exception {
        IntrospectionClient.IntrospectionResult result = verifyWithBody(verifyBodyWithPresence(
            "{\"verified\":true,\"method\":\"webauthn\",\"uv\":true,\"verified_at\":\"2026-07-05T00:00:00Z\"}"));
        assertEquals(new Presence(Boolean.TRUE, "webauthn", Boolean.TRUE, "2026-07-05T00:00:00Z"),
            result.presence());
        assertTrue(result.isPresenceVerified());
    }

    @Test
    void unverifiedPresenceBlockParsesButIsNotVerified() throws Exception {
        // presence-off connection: block present, ceremony never completed
        IntrospectionClient.IntrospectionResult result = verifyWithBody(verifyBodyWithPresence(
            "{\"verified\":false,\"method\":null,\"uv\":null,\"verified_at\":null}"));
        assertEquals(new Presence(Boolean.FALSE, null, null, null), result.presence());
        assertFalse(result.isPresenceVerified());
    }

    @Test
    void absentPresenceIsNullAndNotVerified() throws Exception {
        // Older servers omit the block entirely
        IntrospectionClient.IntrospectionResult result = verifyWithBody(verifyBodyWithPresence(null));
        assertNull(result.presence());
        assertFalse(result.isPresenceVerified());
    }

    @Test
    void verifiedStringTrueIsTreatedAsAbsent() throws Exception {
        // Coerced flags must not count: strictly boolean, like active
        IntrospectionClient.IntrospectionResult result =
            verifyWithBody(verifyBodyWithPresence("{\"verified\":\"true\"}"));
        assertNull(result.presence());
        assertFalse(result.isPresenceVerified());
    }

    @Test
    void verifiedIntegerOneIsTreatedAsAbsent() throws Exception {
        IntrospectionClient.IntrospectionResult result =
            verifyWithBody(verifyBodyWithPresence("{\"verified\":1}"));
        assertNull(result.presence());
        assertFalse(result.isPresenceVerified());
    }

    @Test
    void verifiedNullIsTreatedAsAbsent() throws Exception {
        IntrospectionClient.IntrospectionResult result =
            verifyWithBody(verifyBodyWithPresence("{\"verified\":null}"));
        assertNull(result.presence());
        assertFalse(result.isPresenceVerified());
    }

    @Test
    void emptyPresenceObjectIsTreatedAsAbsent() throws Exception {
        IntrospectionClient.IntrospectionResult result =
            verifyWithBody(verifyBodyWithPresence("{}"));
        assertNull(result.presence());
        assertFalse(result.isPresenceVerified());
    }

    @Test
    void nonObjectPresenceIsTreatedAsAbsent() throws Exception {
        for (String bad : new String[]{"\"verified\"", "[]", "true", "7"}) {
            IntrospectionClient.IntrospectionResult result =
                verifyWithBody(verifyBodyWithPresence(bad));
            assertNull(result.presence(), "presence should be null for: " + bad);
            assertFalse(result.isPresenceVerified());
        }
    }

    @Test
    void mistypedOptionalFieldsAreToleratedAsNull() throws Exception {
        // verified is well-formed; the ceremony detail fields are not
        IntrospectionClient.IntrospectionResult result = verifyWithBody(verifyBodyWithPresence(
            "{\"verified\":true,\"method\":7,\"uv\":\"yes\",\"verified_at\":123}"));
        assertEquals(new Presence(Boolean.TRUE, null, null, null), result.presence());
        assertTrue(result.isPresenceVerified());
    }

    // -------------------------------------------------------------------------
    // isPresenceVerified() matrix via the record directly
    // -------------------------------------------------------------------------

    private static IntrospectionClient.IntrospectionResult resultWithPresence(Presence presence) {
        return new IntrospectionClient.IntrospectionResult(
            "u1", "conn1", List.of("read:orders"), "Bot",
            null, null, null, null, 0L, null, presence, null);
    }

    @Test
    void presenceAbsentIsNotVerified() {
        // Fail closed: absence denies, matching consentGranted()'s posture
        assertFalse(resultWithPresence(null).isPresenceVerified());
    }

    @Test
    void presenceVerifiedTrueIsVerified() {
        assertTrue(resultWithPresence(
            new Presence(Boolean.TRUE, "webauthn", Boolean.TRUE, "2026-07-05T00:00:00Z"))
            .isPresenceVerified());
    }

    @Test
    void presenceVerifiedFalseIsNotVerified() {
        assertFalse(resultWithPresence(
            new Presence(Boolean.FALSE, null, null, null)).isPresenceVerified());
    }

    @Test
    void presenceVerifiedNullFieldIsNotVerified() {
        assertFalse(resultWithPresence(
            new Presence(null, null, null, null)).isPresenceVerified());
    }

    // -------------------------------------------------------------------------
    // @RequirePresence guard via ScopeEnforcementAspect
    // -------------------------------------------------------------------------

    /** Carrier for the annotation instance passed to the aspect. */
    private static final class Guarded {
        @RequirePresence
        void guarded() {}
    }

    private static RequirePresence requirePresenceAnnotation() throws Exception {
        return Guarded.class.getDeclaredMethod("guarded").getAnnotation(RequirePresence.class);
    }

    /** Records what the aspect wrote to the response. */
    private static final class ResponseRecorder {
        int status = 200;
        String contentType;
        final StringWriter body = new StringWriter();
    }

    private static HttpServletRequest fakeRequest(Map<String, Object> attributes) {
        return (HttpServletRequest) Proxy.newProxyInstance(
            PresenceTest.class.getClassLoader(),
            new Class<?>[]{HttpServletRequest.class},
            (proxy, method, args) -> switch (method.getName()) {
                case "getAttribute" -> attributes.get(args[0]);
                case "setAttribute" -> { attributes.put((String) args[0], args[1]); yield null; }
                case "removeAttribute" -> { attributes.remove(args[0]); yield null; }
                case "toString" -> "FakeRequest";
                case "hashCode" -> System.identityHashCode(proxy);
                case "equals" -> proxy == args[0];
                default -> defaultValue(method.getReturnType());
            });
    }

    private static HttpServletResponse fakeResponse(ResponseRecorder recorder) {
        return (HttpServletResponse) Proxy.newProxyInstance(
            PresenceTest.class.getClassLoader(),
            new Class<?>[]{HttpServletResponse.class},
            (proxy, method, args) -> switch (method.getName()) {
                case "setStatus" -> { recorder.status = (int) args[0]; yield null; }
                case "getStatus" -> recorder.status;
                case "setContentType" -> { recorder.contentType = (String) args[0]; yield null; }
                case "getContentType" -> recorder.contentType;
                case "getWriter" -> new PrintWriter(recorder.body);
                case "toString" -> "FakeResponse";
                case "hashCode" -> System.identityHashCode(proxy);
                case "equals" -> proxy == args[0];
                default -> defaultValue(method.getReturnType());
            });
    }

    private static final Object PROCEEDED = new Object();

    private static ProceedingJoinPoint fakeJoinPoint() {
        return (ProceedingJoinPoint) Proxy.newProxyInstance(
            PresenceTest.class.getClassLoader(),
            new Class<?>[]{ProceedingJoinPoint.class},
            (proxy, method, args) -> switch (method.getName()) {
                case "proceed" -> PROCEEDED;
                case "toString" -> "FakeJoinPoint";
                case "hashCode" -> System.identityHashCode(proxy);
                case "equals" -> proxy == args[0];
                default -> defaultValue(method.getReturnType());
            });
    }

    private static Object defaultValue(Class<?> returnType) {
        if (returnType == boolean.class) return false;
        if (returnType == int.class) return 0;
        if (returnType == long.class) return 0L;
        return null;
    }

    /** Binds the fake request/response into the aspect's request context and runs the guard. */
    private static Object runGuard(Map<String, Object> attributes, ResponseRecorder recorder) throws Throwable {
        HttpServletRequest request = fakeRequest(attributes);
        HttpServletResponse response = fakeResponse(recorder);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));
        return new ScopeEnforcementAspect().enforcePresence(fakeJoinPoint(), requirePresenceAnnotation());
    }

    @AfterEach
    void resetRequestContext() {
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    void guardReturns401WithoutAgentToken() throws Throwable {
        // Missing/non-agent token: same posture as @RequireScope
        ResponseRecorder recorder = new ResponseRecorder();
        Object result = runGuard(new HashMap<>(), recorder);
        assertNull(result);
        assertEquals(401, recorder.status);
        assertEquals("application/json", recorder.contentType);
        assertTrue(recorder.body.toString().contains("\"invalid_token\""));
    }

    @Test
    void guardReturns403WhenPresenceAbsent() throws Throwable {
        // Agent token from a server that predates presence: fail closed
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("agentadmit.authType", "agent");
        ResponseRecorder recorder = new ResponseRecorder();
        Object result = runGuard(attributes, recorder);
        assertNull(result);
        assertEquals(403, recorder.status);
        assertEquals("application/json", recorder.contentType);
        String body = recorder.body.toString();
        assertTrue(body.contains("\"error\":\"presence_required\""));
        assertTrue(body.contains(
            "This action requires a connection authorized with human presence verification."));
    }

    @Test
    void guardReturns403WhenPresenceUnverified() throws Throwable {
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("agentadmit.authType", "agent");
        attributes.put("agentadmit.presence", new Presence(Boolean.FALSE, null, null, null));
        ResponseRecorder recorder = new ResponseRecorder();
        Object result = runGuard(attributes, recorder);
        assertNull(result);
        assertEquals(403, recorder.status);
        assertTrue(recorder.body.toString().contains("\"presence_required\""));
    }

    @Test
    void guardReturns403WhenPresenceAttributeIsMistyped() throws Throwable {
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("agentadmit.authType", "agent");
        attributes.put("agentadmit.presence", "verified");
        ResponseRecorder recorder = new ResponseRecorder();
        Object result = runGuard(attributes, recorder);
        assertNull(result);
        assertEquals(403, recorder.status);
        assertTrue(recorder.body.toString().contains("\"presence_required\""));
    }

    @Test
    void guardProceedsWhenPresenceVerified() throws Throwable {
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("agentadmit.authType", "agent");
        attributes.put("agentadmit.presence",
            new Presence(Boolean.TRUE, "webauthn", Boolean.TRUE, "2026-07-05T00:00:00Z"));
        ResponseRecorder recorder = new ResponseRecorder();
        Object result = runGuard(attributes, recorder);
        assertSame(PROCEEDED, result);
        assertEquals(200, recorder.status);
    }

    // -------------------------------------------------------------------------
    // Filter exposes the presence attribute for the guard
    // -------------------------------------------------------------------------

    @Test
    void filterExposesPresenceRequestAttribute() throws Exception {
        AgentAdmitConfig config = configWith();
        Presence presence = new Presence(Boolean.TRUE, "webauthn", Boolean.TRUE, "2026-07-05T00:00:00Z");
        IntrospectionClient client = new IntrospectionClient(config) {
            @Override
            public IntrospectionResult verify(String token) {
                return new IntrospectionResult("user_1", "conn_1", List.of("read:orders"),
                    "TestAgent", null, null, null, null, 0L, null, presence, null);
            }
        };

        Map<String, Object> attributes = new HashMap<>();
        HttpServletRequest request = (HttpServletRequest) Proxy.newProxyInstance(
            PresenceTest.class.getClassLoader(),
            new Class<?>[]{HttpServletRequest.class},
            (proxy, method, args) -> switch (method.getName()) {
                case "getHeader" ->
                    "Authorization".equalsIgnoreCase((String) args[0]) ? "Bearer ag_at_mytoken" : null;
                case "getAttribute" -> attributes.get(args[0]);
                case "setAttribute" -> { attributes.put((String) args[0], args[1]); yield null; }
                case "toString" -> "FakeRequest";
                case "hashCode" -> System.identityHashCode(proxy);
                case "equals" -> proxy == args[0];
                default -> defaultValue(method.getReturnType());
            });
        ResponseRecorder recorder = new ResponseRecorder();
        FilterChain chain = (rq, rs) -> {};

        new AgentAdmitFilter(config, client).doFilter(request, fakeResponse(recorder), chain);

        assertEquals("agent", attributes.get("agentadmit.authType"));
        assertEquals(presence, attributes.get("agentadmit.presence"));
    }
}
