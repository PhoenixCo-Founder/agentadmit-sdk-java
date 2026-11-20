package com.agentadmit;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.slf4j.LoggerFactory;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import javax.net.ssl.SSLSession;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * SDK 1.15.0.
 *
 * Row A: {@code confirmation.enrollment_required} on the
 * {@code confirmation_required} refusal is kept strictly (a JSON boolean
 * only), on the typed {@link ActionConfirmation} and in the 403 body; when it
 * is {@code true} the agent is told the link alone cannot be used.
 *
 * Row B: {@link TokensClient#createOwnerLink(String, String)}.
 */
class OwnerLinkTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final String ENROLLMENT_SENTENCE =
        "This action requires a fresh human confirmation, and this user has no passkey on file for the app yet, "
            + "so the confirmation link alone cannot be used. Ask the user to open the request from inside the app. "
            + "After they confirm, retry with the X-AgentAdmit-Action-Attestation header.";

    private static final String OLD_SENTENCE =
        "This action requires a fresh human confirmation. Give the confirmation link to the user, "
            + "then retry with the X-AgentAdmit-Action-Attestation header.";

    private static HttpResponse<String> stubResponse(int status, String body) {
        HttpHeaders headers = HttpHeaders.of(Map.of(), (a, b) -> true);
        return new HttpResponse<>() {
            @Override public int statusCode() { return status; }
            @Override public HttpRequest request() { return null; }
            @Override public Optional<HttpResponse<String>> previousResponse() { return Optional.empty(); }
            @Override public HttpHeaders headers() { return headers; }
            @Override public String body() { return body; }
            @Override public Optional<SSLSession> sslSession() { return Optional.empty(); }
            @Override public URI uri() { return URI.create("https://agentadmit.example/api/v1/x"); }
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
    // Row A
    // -------------------------------------------------------------------------

    private static class StubVerifyClient extends IntrospectionClient {
        private final HttpResponse<String> response;

        StubVerifyClient(String body) {
            super(configWith());
            this.response = stubResponse(200, body);
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

    private static String refusal(String enrollmentFragment, String hostedDescription) {
        return "{\"active\":true,\"error\":\"confirmation_required\","
            + (hostedDescription != null ? "\"error_description\":\"" + hostedDescription + "\"," : "")
            + "\"confirmation\":{\"action_session_id\":\"asess_abc\","
            + "\"action_session_url\":\"https://agentadmit.com/confirm/action/asess_abc\","
            + enrollmentFragment
            + "\"expires_at\":\"e\",\"scope\":\"write:payments\",\"method\":null,\"endpoint\":null,"
            + "\"request_digest\":null,\"summary\":null}}";
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> filter403(String verifyBody) throws Exception {
        AgentAdmitFilter filter = new AgentAdmitFilter(configWith(), new StubVerifyClient(verifyBody), r -> "write:payments");
        MockHttpServletRequest req = new MockHttpServletRequest("POST", "/api/payments");
        req.addHeader("Authorization", "Bearer ag_at_dummy_token");
        req.setContentType("application/json");
        req.setContent("{}".getBytes(StandardCharsets.UTF_8));
        MockFilterChain chain = new MockFilterChain();
        MockHttpServletResponse resp = new MockHttpServletResponse();
        filter.doFilter(req, resp, chain);
        assertNull(chain.getRequest(), "a refusal never reaches the handler");
        assertEquals(403, resp.getStatus());
        return MAPPER.readValue(resp.getContentAsString(), Map.class);
    }

    private static AgentAdmitException typedRefusal(String verifyBody) {
        return assertThrows(AgentAdmitException.class,
            () -> new StubVerifyClient(verifyBody).verify("ag_at_dummy_token",
                VerifyTelemetry.of("write:payments", "/api/payments", "POST")));
    }

    @ParameterizedTest(name = "wire {0}")
    @CsvSource(delimiter = '|', value = {
        "'\"enrollment_required\":true,'   | true",
        "'\"enrollment_required\":false,'  | false",
        "''                                | ",
        "'\"enrollment_required\":null,'   | ",
        "'\"enrollment_required\":\"true\",' | ",
        "'\"enrollment_required\":1,'      | ",
        "'\"enrollment_required\":0,'      | ",
        "'\"enrollment_required\":{},'     | ",
        "'\"enrollment_required\":[],'     | ",
    })
    @SuppressWarnings("unchecked")
    void enrollmentRequiredMatrix(String fragment, Boolean expected) throws Exception {
        String verifyBody = refusal(fragment, null);

        AgentAdmitException e = typedRefusal(verifyBody);
        AgentAdmitException.ConfirmationRequiredDenial denial =
            assertInstanceOf(AgentAdmitException.ConfirmationRequiredDenial.class, e);
        assertEquals(expected, denial.getConfirmation().enrollmentRequired());

        Map<String, Object> body = filter403(verifyBody);
        Map<String, Object> confirmation = (Map<String, Object>) body.get("confirmation");
        assertNotNull(confirmation);
        assertEquals("https://agentadmit.com/confirm/action/asess_abc", confirmation.get("action_session_url"));
        if (expected == null) {
            assertFalse(confirmation.containsKey("enrollment_required"),
                "not stated on the wire = key absent in the 403 body");
        } else {
            assertEquals(expected, confirmation.get("enrollment_required"));
        }
        // The relayed body is the one the denial carries.
        assertEquals(body, MAPPER.readValue(denial.getResponseBody(), Map.class));
    }

    @Test
    void blockMissingTheUrlIsStillDroppedWhole() throws Exception {
        String verifyBody = "{\"active\":true,\"error\":\"confirmation_required\","
            + "\"confirmation\":{\"action_session_id\":\"asess_abc\",\"enrollment_required\":true,"
            + "\"expires_at\":\"e\",\"scope\":\"write:payments\"}}";
        AgentAdmitException e = typedRefusal(verifyBody);
        assertFalse(e instanceof AgentAdmitException.ConfirmationRequiredDenial);
        assertInstanceOf(AgentAdmitException.ActiveErrorDenial.class, e);
        Map<String, Object> body = filter403(verifyBody);
        assertFalse(body.containsKey("confirmation"));
        assertEquals(OLD_SENTENCE, body.get("error_description"));
    }

    @Test
    void sentenceForTrueAndUnchangedOtherwise() throws Exception {
        assertEquals(ENROLLMENT_SENTENCE, filter403(refusal("\"enrollment_required\":true,", null)).get("error_description"));
        assertEquals(ENROLLMENT_SENTENCE, typedRefusal(refusal("\"enrollment_required\":true,", null)).getMessage());
        assertEquals(OLD_SENTENCE, filter403(refusal("\"enrollment_required\":false,", null)).get("error_description"));
        assertEquals(OLD_SENTENCE, filter403(refusal("", null)).get("error_description"));
        // The hosted description still wins for false and absent, as before;
        // for true the enrollment sentence replaces it.
        assertEquals("hosted words", filter403(refusal("\"enrollment_required\":false,", "hosted words")).get("error_description"));
        assertEquals("hosted words", filter403(refusal("", "hosted words")).get("error_description"));
        assertEquals(ENROLLMENT_SENTENCE, filter403(refusal("\"enrollment_required\":true,", "hosted words")).get("error_description"));
    }

    @Test
    void previousConstructorStillWorks() {
        ActionConfirmation c = new ActionConfirmation("asess_abc", "u", "e", "s", null, null, null, null);
        assertNull(c.enrollmentRequired());
        assertFalse(c.toWireMap().containsKey("enrollment_required"));
    }

    // -------------------------------------------------------------------------
    // Row B
    // -------------------------------------------------------------------------

    private static final String SESSION = "asess_0123456789abcdef";

    private static class CapturingTokensClient extends TokensClient {
        final List<String> urls = new ArrayList<>();
        final List<String> bodies = new ArrayList<>();
        private final int status;
        private final String responseBody;
        private final boolean failNetwork;

        CapturingTokensClient(int status, String responseBody) {
            this(status, responseBody, false);
        }

        CapturingTokensClient(int status, String responseBody, boolean failNetwork) {
            super(configWith());
            this.status = status;
            this.responseBody = responseBody;
            this.failNetwork = failNetwork;
        }

        @Override
        HttpResponse<String> sendPost(String url, String jsonBody) throws Exception {
            urls.add(url);
            bodies.add(jsonBody);
            if (failNetwork) throw new java.io.IOException("connection reset");
            return stubResponse(status, responseBody);
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void requestShape() throws Exception {
        CapturingTokensClient client = new CapturingTokensClient(201,
            "{\"action_session_id\":\"x\",\"owner_session_url\":\"https://agentadmit.com/o#t=1\","
                + "\"enrollment_required\":true,\"enrollment_reason\":\"no_passkey\",\"expires_at\":\"e\"}");
        // An id with characters that need encoding proves it goes through an
        // encoder (real ids only use - and _).
        client.createOwnerLink("asess_a/b c-_0123456789", "user_42");
        assertEquals("https://api.agentadmit.com/api/v1/action-sessions/asess_a%2Fb%20c-_0123456789/owner-link",
            client.urls.get(0));
        assertEquals(Map.of("app_user_id", "user_42"), MAPPER.readValue(client.bodies.get(0), Map.class));

        client.createOwnerLink(SESSION, "user_42");
        assertEquals("https://api.agentadmit.com/api/v1/action-sessions/" + SESSION + "/owner-link", client.urls.get(1));
    }

    @Test
    void sendPostCarriesMethodBearerAndContentType() throws Exception {
        // The production sendPost builds a POST with the Bearer key and JSON
        // content type; capture the built request through a local server.
        com.sun.net.httpserver.HttpServer server =
            com.sun.net.httpserver.HttpServer.create(new java.net.InetSocketAddress("127.0.0.1", 0), 0);
        List<String> seen = new ArrayList<>();
        server.createContext("/", exchange -> {
            seen.add(exchange.getRequestMethod());
            seen.add(exchange.getRequestURI().getRawPath());
            seen.add(exchange.getRequestHeaders().getFirst("Authorization"));
            seen.add(exchange.getRequestHeaders().getFirst("Content-Type"));
            seen.add(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            byte[] out = ("{\"action_session_id\":\"" + SESSION + "\",\"owner_session_url\":\"https://x/o\","
                + "\"enrollment_required\":false,\"expires_at\":\"e\"}").getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, out.length);
            exchange.getResponseBody().write(out);
            exchange.close();
        });
        server.start();
        try {
            AgentAdmitConfig config = configWith();
            config.setApiUrl("http://127.0.0.1:" + server.getAddress().getPort());
            OwnerLink link = new TokensClient(config).createOwnerLink(SESSION, "user_42");
            assertEquals("https://x/o", link.ownerSessionUrl());
        } finally {
            server.stop(0);
        }
        assertEquals("POST", seen.get(0));
        assertEquals("/api/v1/action-sessions/" + SESSION + "/owner-link", seen.get(1));
        assertEquals("Bearer aa_test_dummy", seen.get(2));
        assertEquals("application/json", seen.get(3));
        assertEquals("{\"app_user_id\":\"user_42\"}", seen.get(4));
    }

    @Test
    void createdAndOkResults() {
        OwnerLink created = new CapturingTokensClient(201,
            "{\"action_session_id\":\"" + SESSION + "\",\"owner_session_url\":\"https://agentadmit.com/o#t=1\","
                + "\"enrollment_required\":true,\"enrollment_reason\":\"no_eligible_authenticator\","
                + "\"expires_at\":\"2026-11-20T18:00:00.000Z\"}").createOwnerLink(SESSION, "user_42");
        assertEquals(new OwnerLink(SESSION, "https://agentadmit.com/o#t=1", true, "no_eligible_authenticator",
            "2026-11-20T18:00:00.000Z"), created);

        OwnerLink ok = new CapturingTokensClient(200,
            "{\"action_session_id\":\"" + SESSION + "\",\"owner_session_url\":\"https://agentadmit.com/confirm/action/x\","
                + "\"enrollment_required\":false,\"expires_at\":\"e\"}").createOwnerLink(SESSION, "user_42");
        assertFalse(ok.enrollmentRequired());
        assertNull(ok.enrollmentReason());
        assertEquals("https://agentadmit.com/confirm/action/x", ok.ownerSessionUrl());
        assertFalse(created.toString().contains("agentadmit.com/o"), "toString leaves the URL out");
    }

    @ParameterizedTest(name = "{0} {1}")
    @CsvSource({
        "401, invalid_api_key",
        "403, api_key_not_app_linked",
        "404, not_found",
        "409, already_consumed",
        "409, already_verified",
        "410, session_expired",
        "429, rate_limited",
    })
    void errorStatusesMapToApiError(int status, String code) {
        CapturingTokensClient client = new CapturingTokensClient(status,
            "{\"error\":\"" + code + "\",\"error_description\":\"d\"}");
        AgentAdmitException.ApiError e = assertThrows(AgentAdmitException.ApiError.class,
            () -> client.createOwnerLink(SESSION, "user_42"));
        assertEquals(status, e.getStatusCode());
        assertEquals(code, e.getErrorCode());
        assertEquals(1, client.urls.size(), "no retry on a 4xx");
    }

    @Test
    void serverErrorAndNetworkFailure() {
        CapturingTokensClient five = new CapturingTokensClient(503, "upstream");
        AgentAdmitException.ApiError e = assertThrows(AgentAdmitException.ApiError.class,
            () -> five.createOwnerLink(SESSION, "user_42"));
        assertEquals(503, e.getStatusCode());
        assertNull(e.getErrorCode());

        CapturingTokensClient down = new CapturingTokensClient(0, null, true);
        AgentAdmitException n = assertThrows(AgentAdmitException.class,
            () -> down.createOwnerLink(SESSION, "user_42"));
        assertEquals(502, n.getStatusCode());
    }

    @Test
    void argumentErrorsMakeNoRequest() {
        CapturingTokensClient client = new CapturingTokensClient(201, "{}");
        assertThrows(IllegalArgumentException.class, () -> client.createOwnerLink("sess_0123456789abcdefgh", "u"));
        assertThrows(IllegalArgumentException.class, () -> client.createOwnerLink("asess_short", "u"));
        assertThrows(IllegalArgumentException.class, () -> client.createOwnerLink(null, "u"));
        assertThrows(IllegalArgumentException.class, () -> client.createOwnerLink(SESSION, ""));
        assertThrows(IllegalArgumentException.class, () -> client.createOwnerLink(SESSION, null));
        assertThrows(IllegalArgumentException.class, () -> client.createOwnerLink(SESSION, "u".repeat(256)));
        assertTrue(client.urls.isEmpty(), "no request before the arguments pass");
    }

    @Test
    void malformed2xxIsAnErrorNeverAPartialResult() {
        String[] bodies = {
            "{\"action_session_id\":\"x\",\"enrollment_required\":true,\"expires_at\":\"e\"}",
            "{\"action_session_id\":\"x\",\"owner_session_url\":5,\"enrollment_required\":true}",
            "{\"action_session_id\":\"x\",\"owner_session_url\":\"https://agentadmit.com/o#t=secret\",\"expires_at\":\"e\"}",
            "{\"owner_session_url\":\"https://agentadmit.com/o#t=secret\",\"enrollment_required\":\"true\"}",
            "not json https://agentadmit.com/o#t=secret",
            "[]",
            // Same rule as the other five SDKs: the id and the expiry are required too.
            "{\"owner_session_url\":\"https://agentadmit.com/o#t=secret\",\"enrollment_required\":true,\"expires_at\":\"e\"}",
            "{\"action_session_id\":\"x\",\"owner_session_url\":\"https://agentadmit.com/o#t=secret\",\"enrollment_required\":true}",
            "{\"action_session_id\":7,\"owner_session_url\":\"https://agentadmit.com/o#t=secret\",\"enrollment_required\":false,\"expires_at\":\"e\"}",
        };
        for (String body : bodies) {
            AgentAdmitException e = assertThrows(AgentAdmitException.class,
                () -> new CapturingTokensClient(201, body).createOwnerLink(SESSION, "user_42"), body);
            assertEquals(502, e.getStatusCode());
            assertFalse(e.getMessage().contains("secret") || e.getMessage().contains("agentadmit.com/o"));
        }
    }

    @Test
    void reasonIsKeptOnlyWithAnEnrollment() {
        // A stray enrollment_reason on a "passkey already on file" answer is not copied through.
        OwnerLink link = new CapturingTokensClient(200, "{\"action_session_id\":\"" + SESSION
            + "\",\"owner_session_url\":\"https://agentadmit.com/confirm/action/x\",\"enrollment_required\":false,"
            + "\"enrollment_reason\":\"no_passkey\",\"expires_at\":\"2026-11-20T18:30:00.000Z\"}")
            .createOwnerLink(SESSION, "user_42");
        assertFalse(link.enrollmentRequired());
        assertNull(link.enrollmentReason());
    }

    @Test
    void neverLogsTheOwnerSessionUrl() {
        Logger logger = (Logger) LoggerFactory.getLogger(TokensClient.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        try {
            String url = "https://agentadmit.com/confirm/owner/asess_x#t=secret_fragment";
            new CapturingTokensClient(201, "{\"action_session_id\":\"" + SESSION + "\",\"owner_session_url\":\"" + url
                    + "\",\"enrollment_required\":true,\"expires_at\":\"2026-11-20T18:30:00.000Z\"}")
                .createOwnerLink(SESSION, "user_42");
            assertThrows(AgentAdmitException.class, () -> new CapturingTokensClient(201,
                "{\"owner_session_url\":\"" + url + "\"}").createOwnerLink(SESSION, "user_42"));
            assertThrows(AgentAdmitException.class, () -> new CapturingTokensClient(201,
                "garbage " + url).createOwnerLink(SESSION, "user_42"));
            assertThrows(AgentAdmitException.class, () -> new CapturingTokensClient(409,
                "{\"error\":\"already_consumed\",\"owner_session_url\":\"" + url + "\"}").createOwnerLink(SESSION, "user_42"));
            assertFalse(appender.list.isEmpty(), "the error paths log their path and status");
            for (ILoggingEvent event : appender.list) {
                String line = event.getFormattedMessage();
                assertFalse(line.contains("secret_fragment") || line.contains("confirm/owner"), line);
                assertTrue(line.contains("/api/v1/action-sessions/" + SESSION + "/owner-link"), line);
            }
        } finally {
            logger.detachAppender(appender);
        }
    }
}
