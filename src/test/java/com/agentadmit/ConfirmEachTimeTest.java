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
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Confirm-each-time (SDK 1.11.0). A scope marked {@code confirm_each_time} is
 * granted, but every call that exercises it needs a fresh human confirmation.
 * The SDK must (1) relay the hosted {@code confirmation_required} refusal as a
 * 403 carrying the staged ceremony, (2) fail closed with NO confirmation block
 * when that block is malformed, (3) forward the agent's
 * {@code X-AgentAdmit-Action-Attestation} header on the retry, (4) digest the
 * RAW request body while leaving it readable downstream, (5) carry the app's
 * action summary, and (6) surface a CONSUMED confirmation only when the wire
 * block is strictly typed.
 */
class ConfirmEachTimeTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final String CONFIRMATION_JSON =
        "{\"action_session_id\":\"asess_abc\","
            + "\"action_session_url\":\"https://agentadmit.com/confirm/action/asess_abc\","
            + "\"expires_at\":\"2026-09-02T18:30:00.000Z\","
            + "\"scope\":\"write:payments\",\"method\":\"POST\",\"endpoint\":\"/api/payments\","
            + "\"request_digest\":\"sha256:deadbeef\",\"summary\":\"Pay Alex $50\"}";

    private static final String CONFIRMATION_REQUIRED_BODY =
        "{\"active\":true,\"error\":\"confirmation_required\","
            + "\"confirmation\":" + CONFIRMATION_JSON + ","
            + "\"attestation_status\":\"action_mismatch\","
            + "\"attestation_description\":\"That confirmation was for a different action.\","
            + "\"renewal\":\"The human confirms on the hosted page with their passkey.\","
            + "\"scopes\":[\"leak\"],\"user_id\":\"u1\"}";

    private static final String DECLINED_JSON =
        "{\"action_session_id\":\"asess_abc\","
            + "\"declined_at\":\"2026-09-22T21:35:42.000Z\","
            + "\"hold_until\":\"2026-09-22T21:50:42.000Z\","
            + "\"scope\":\"write:payments\",\"method\":\"POST\",\"endpoint\":\"/api/payments\","
            + "\"request_digest\":\"sha256:deadbeef\",\"summary\":\"Pay Alex $50\"}";

    private static final String CONFIRMATION_DECLINED_BODY =
        "{\"active\":true,\"error\":\"confirmation_declined\","
            + "\"error_description\":\"The user declined this action on the hosted confirmation page. Do not retry it unless the user asks you to; no new confirmation can be staged for this action until 2026-09-22T21:50:42.000Z.\","
            + "\"declined\":" + DECLINED_JSON + ","
            + "\"attestation_status\":\"declined\","
            + "\"attestation_description\":\"The user declined this action.\","
            + "\"renewal\":\"Only the user can lift a decline. After the hold ends, a retry stages a fresh confirmation for them to approve or decline again.\","
            + "\"scopes\":[\"leak\"],\"user_id\":\"u1\"}";

    private static final String ACTIVE_BODY =
        "{\"active\":true,\"user_id\":\"user_1\",\"connection_id\":\"conn_1\","
            + "\"scopes\":[\"write:payments\"],\"agent_label\":\"Test Agent\"}";

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

    /** Captures the exact verify body the production path sends, then answers with a stub. */
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

    private static MockHttpServletRequest agentPost(String uri, String body) {
        MockHttpServletRequest req = new MockHttpServletRequest("POST", uri);
        req.addHeader("Authorization", "Bearer ag_at_dummy_token");
        req.setContentType("application/json");
        if (body != null) req.setContent(body.getBytes(StandardCharsets.UTF_8));
        return req;
    }

    // -------------------------------------------------------------------------
    // §2: the confirmation_required refusal passes the staged ceremony through
    // -------------------------------------------------------------------------

    @Test
    @SuppressWarnings("unchecked")
    void confirmationRequiredIsA403CarryingTheStagedCeremony() throws Exception {
        CapturingClient client = new CapturingClient(stubResponse(200, CONFIRMATION_REQUIRED_BODY));
        AgentAdmitFilter filter = new AgentAdmitFilter(configWith(), client, r -> "write:payments");
        MockFilterChain chain = new MockFilterChain();
        MockHttpServletResponse resp = new MockHttpServletResponse();

        filter.doFilter(agentPost("/api/payments", "{\"amount\":50}"), resp, chain);

        assertNull(chain.getRequest(), "a refusal never reaches the handler");
        assertEquals(403, resp.getStatus());
        Map<String, Object> body = MAPPER.readValue(resp.getContentAsString(), Map.class);
        assertEquals("confirmation_required", body.get("error"));
        assertEquals(
            "This action requires a fresh human confirmation. Give the confirmation link to the user, "
                + "then retry with the X-AgentAdmit-Action-Attestation header.",
            body.get("error_description"));
        Map<String, Object> confirmation = (Map<String, Object>) body.get("confirmation");
        assertEquals(MAPPER.readValue(CONFIRMATION_JSON, Map.class), confirmation,
            "the confirmation block is relayed field-for-field");
        assertEquals("action_mismatch", body.get("attestation_status"));
        assertEquals("That confirmation was for a different action.", body.get("attestation_description"));
        assertEquals("The human confirms on the hosted page with their passkey.", body.get("renewal"));
        assertFalse(body.containsKey("scopes"), "nothing else from the wire leaks into the refusal");
        assertFalse(body.containsKey("user_id"));
    }

    @Test
    void confirmationRequiredThrowsTheTypedDenialFromTheVerifyClient() {
        CapturingClient client = new CapturingClient(stubResponse(200, CONFIRMATION_REQUIRED_BODY));

        AgentAdmitException.ConfirmationRequiredDenial denial =
            assertThrows(AgentAdmitException.ConfirmationRequiredDenial.class,
                () -> client.verify("ag_at_dummy_token", VerifyTelemetry.of("write:payments", "/api/payments", "POST")));

        assertInstanceOf(AgentAdmitException.ActiveErrorDenial.class, denial,
            "typed refusal still fails closed through the existing catch");
        assertEquals(403, denial.getStatusCode());
        assertEquals("confirmation_required", denial.getErrorCode());
        assertEquals("action_mismatch", denial.getAttestationStatus());
        ActionConfirmation c = denial.getConfirmation();
        assertEquals("asess_abc", c.actionSessionId());
        assertEquals("https://agentadmit.com/confirm/action/asess_abc", c.actionSessionUrl());
        assertEquals("2026-09-02T18:30:00.000Z", c.expiresAt());
        assertEquals("write:payments", c.scope());
        assertEquals("POST", c.method());
        assertEquals("/api/payments", c.endpoint());
        assertEquals("sha256:deadbeef", c.requestDigest());
        assertEquals("Pay Alex $50", c.summary());
    }

    @Test
    @SuppressWarnings("unchecked")
    void malformedConfirmationBlockFailsClosedWithNoBlock() throws Exception {
        String malformed = "{\"active\":true,\"error\":\"confirmation_required\","
            + "\"confirmation\":{\"action_session_id\":\"asess_abc\",\"action_session_url\":17,"
            + "\"expires_at\":\"e\",\"scope\":\"s\"}}";
        CapturingClient client = new CapturingClient(stubResponse(200, malformed));
        AgentAdmitFilter filter = new AgentAdmitFilter(configWith(), client, r -> "write:payments");
        MockFilterChain chain = new MockFilterChain();
        MockHttpServletResponse resp = new MockHttpServletResponse();

        filter.doFilter(agentPost("/api/payments", "{}"), resp, chain);

        assertNull(chain.getRequest());
        assertEquals(403, resp.getStatus());
        Map<String, Object> body = MAPPER.readValue(resp.getContentAsString(), Map.class);
        assertEquals("confirmation_required", body.get("error"));
        assertFalse(body.containsKey("confirmation"), "a malformed ceremony is never relayed");

        AgentAdmitException.ActiveErrorDenial denial =
            assertThrows(AgentAdmitException.ActiveErrorDenial.class,
                () -> client.verify("ag_at_dummy_token", VerifyTelemetry.of("write:payments", "/p", "POST")));
        assertFalse(denial instanceof AgentAdmitException.ConfirmationRequiredDenial,
            "no typed denial without a well-formed block");
    }

    @Test
    void strictParsingOfTheConfirmationBlock() {
        assertNull(ActionConfirmation.fromVerifyData(null));
        assertNull(ActionConfirmation.fromVerifyData("not-an-object"));
        assertNull(ActionConfirmation.fromVerifyData(Map.of("x", 1)));
        ActionConfirmation minimal = ActionConfirmation.fromVerifyData(Map.of(
            "action_session_id", "a", "action_session_url", "u", "expires_at", "e", "scope", "s"));
        assertNotNull(minimal);
        assertNull(minimal.method());
        assertNull(minimal.endpoint());
        assertNull(minimal.requestDigest());
        assertNull(minimal.summary());
    }

    @Test
    @SuppressWarnings("unchecked")
    void otherActiveRefusalsKeepTheirExistingFailClosedShape() throws Exception {
        CapturingClient client = new CapturingClient(stubResponse(200,
            "{\"active\":true,\"error\":\"confirmation_policy_unavailable\"}"));
        AgentAdmitFilter filter = new AgentAdmitFilter(configWith(), client, r -> "write:payments");
        MockFilterChain chain = new MockFilterChain();
        MockHttpServletResponse resp = new MockHttpServletResponse();

        filter.doFilter(agentPost("/api/payments", "{}"), resp, chain);

        assertEquals(403, resp.getStatus());
        assertNull(chain.getRequest());
        Map<String, Object> body = MAPPER.readValue(resp.getContentAsString(), Map.class);
        assertEquals("confirmation_policy_unavailable", body.get("error"));
        assertEquals("Call refused by the authorization service.", body.get("error_description"));
        assertFalse(body.containsKey("confirmation"));
    }

    // -------------------------------------------------------------------------
    // §1/§3: attestation header forwarding — always, with or without a summary
    // -------------------------------------------------------------------------

    @Test
    void attestationHeaderIsForwardedTrimmedFirstValueAndCapped() throws Exception {
        CapturingClient client = new CapturingClient(stubResponse(200, ACTIVE_BODY));
        AgentAdmitFilter filter = new AgentAdmitFilter(configWith(), client, r -> "write:payments");
        MockHttpServletRequest req = agentPost("/api/payments", "{\"amount\":50}");
        req.addHeader("x-agentadmit-action-attestation", "  asess_abc  ");
        req.addHeader("X-AgentAdmit-Action-Attestation", "asess_second");

        filter.doFilter(req, new MockHttpServletResponse(), new MockFilterChain());

        assertEquals("asess_abc", client.lastBody.get("action_attestation_id"),
            "case-insensitive lookup, first value, trimmed");
        assertFalse(client.lastBody.containsKey("request_digest"),
            "no summary configured: no digest is sent");
        assertFalse(client.lastBody.containsKey("action_summary"));
    }

    @Test
    void attestationIdIsCappedAt120Characters() {
        String overlong = "a".repeat(200);
        MockHttpServletRequest req = agentPost("/api/payments", "{}");
        req.addHeader(VerifyTelemetry.ACTION_ATTESTATION_HEADER, overlong);

        VerifyTelemetry telemetry = VerifyTelemetry.forRequest(req, "write:payments");

        assertEquals(120, telemetry.actionAttestationId().length());
        assertEquals("a".repeat(120), telemetry.actionAttestationId());
    }

    @Test
    void blankOrAbsentAttestationHeaderIsOmitted() throws Exception {
        CapturingClient client = new CapturingClient(stubResponse(200, ACTIVE_BODY));
        AgentAdmitFilter filter = new AgentAdmitFilter(configWith(), client, r -> "write:payments");
        MockHttpServletRequest req = agentPost("/api/payments", "{}");
        req.addHeader(VerifyTelemetry.ACTION_ATTESTATION_HEADER, "   ");

        filter.doFilter(req, new MockHttpServletResponse(), new MockFilterChain());

        assertFalse(client.lastBody.containsKey("action_attestation_id"));
        assertNull(VerifyTelemetry.actionAttestationId(agentPost("/api/payments", "{}")));
        assertNull(VerifyTelemetry.actionAttestationId(null));
    }

    // -------------------------------------------------------------------------
    // §1/§3: digest over the RAW body, body still readable downstream, summary
    // -------------------------------------------------------------------------

    @Test
    void actionSummaryOptionSendsDigestAndSummaryAndLeavesTheBodyReadable() throws Exception {
        CapturingClient client = new CapturingClient(stubResponse(200, ACTIVE_BODY));
        String payload = "{\"trainer\":\"alex\",\"amount\":50}";
        AgentAdmitFilter filter = new AgentAdmitFilter(
            configWith(), client, r -> "write:payments",
            AgentAdmitFilter.Options.withActionSummary(
                (request, body) -> "Pay for " + new String(body, StandardCharsets.UTF_8).length() + " bytes"));
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(agentPost("/api/payments", payload), new MockHttpServletResponse(), chain);

        assertNotNull(chain.getRequest(), "an accepted call still reaches the handler");
        String digest = (String) client.lastBody.get("request_digest");
        assertNotNull(digest);
        assertTrue(digest.startsWith("sha256:"));
        assertEquals("sha256:".length() + 64, digest.length());
        assertEquals(VerifyTelemetry.requestDigestFor(payload.getBytes(StandardCharsets.UTF_8)), digest,
            "the digest commits to the RAW body bytes");
        assertEquals("Pay for " + payload.length() + " bytes", client.lastBody.get("action_summary"));

        // The downstream handler still sees the untouched body.
        assertEquals(payload,
            new String(chain.getRequest().getInputStream().readAllBytes(), StandardCharsets.UTF_8));
    }

    @Test
    void bodyIsAlsoReadableThroughGetReader() throws Exception {
        CapturingClient client = new CapturingClient(stubResponse(200, ACTIVE_BODY));
        String payload = "{\"amount\":50}";
        AgentAdmitFilter filter = new AgentAdmitFilter(
            configWith(), client, r -> "write:payments",
            AgentAdmitFilter.Options.withActionSummary((request, body) -> "Pay"));
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(agentPost("/api/payments", payload), new MockHttpServletResponse(), chain);

        assertEquals(payload, ((jakarta.servlet.http.HttpServletRequest) chain.getRequest()).getReader().readLine());
    }

    @Test
    void summaryIsTrimmedAndCappedAt200Characters() throws Exception {
        CapturingClient client = new CapturingClient(stubResponse(200, ACTIVE_BODY));
        String overlong = "  " + "s".repeat(300) + "  ";
        AgentAdmitFilter filter = new AgentAdmitFilter(
            configWith(), client, r -> "write:payments",
            AgentAdmitFilter.Options.withActionSummary((request, body) -> overlong));

        filter.doFilter(agentPost("/api/payments", "{}"), new MockHttpServletResponse(), new MockFilterChain());

        assertEquals("s".repeat(200), client.lastBody.get("action_summary"));
    }

    @Test
    void aSummarySupplierThatThrowsNeverBlocksTheCallAndTheDigestStillRides() throws Exception {
        CapturingClient client = new CapturingClient(stubResponse(200, ACTIVE_BODY));
        AgentAdmitFilter filter = new AgentAdmitFilter(
            configWith(), client, r -> "write:payments",
            AgentAdmitFilter.Options.withActionSummary((request, body) -> {
                throw new IllegalStateException("boom");
            }));
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(agentPost("/api/payments", "{\"a\":1}"), new MockHttpServletResponse(), chain);

        assertNotNull(chain.getRequest());
        assertFalse(client.lastBody.containsKey("action_summary"));
        assertTrue(((String) client.lastBody.get("request_digest")).startsWith("sha256:"));
    }

    @Test
    void blankSummaryAndEmptyBodyAreOmitted() throws Exception {
        CapturingClient client = new CapturingClient(stubResponse(200, ACTIVE_BODY));
        AgentAdmitFilter filter = new AgentAdmitFilter(
            configWith(), client, r -> "write:payments",
            AgentAdmitFilter.Options.withActionSummary((request, body) -> "   "));

        filter.doFilter(agentPost("/api/payments", null), new MockHttpServletResponse(), new MockFilterChain());

        assertFalse(client.lastBody.containsKey("action_summary"));
        assertFalse(client.lastBody.containsKey("request_digest"), "no body, no digest");
        assertNull(VerifyTelemetry.requestDigestFor(new byte[0]));
        assertNull(VerifyTelemetry.requestDigestFor(null));
    }

    @Test
    void defaultOptionsChangeNothingForOrdinaryRoutes() throws Exception {
        CapturingClient client = new CapturingClient(stubResponse(200, ACTIVE_BODY));
        AgentAdmitFilter filter = new AgentAdmitFilter(configWith(), client, r -> "write:payments");

        filter.doFilter(agentPost("/api/payments", "{\"a\":1}"), new MockHttpServletResponse(), new MockFilterChain());

        for (String key : new String[]{"action_attestation_id", "request_digest", "action_summary"}) {
            assertFalse(client.lastBody.containsKey(key), key + " must be omitted");
        }
        assertEquals("write:payments", client.lastBody.get("scope_used"));
        assertEquals("/api/payments", client.lastBody.get("endpoint"));
        assertEquals("POST", client.lastBody.get("method"));
    }

    @Test
    void digestIsSha256OfTheRawBytes() {
        assertEquals(
            "sha256:2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
            VerifyTelemetry.requestDigestFor("foo".getBytes(StandardCharsets.UTF_8)));
    }

    // -------------------------------------------------------------------------
    // §4: a CONSUMED confirmation is surfaced only when strictly typed
    // -------------------------------------------------------------------------

    @Test
    void consumedConfirmationIsSurfacedAsAContextAttribute() throws Exception {
        String body = "{\"active\":true,\"user_id\":\"u1\",\"connection_id\":\"c1\","
            + "\"scopes\":[\"write:payments\"],"
            + "\"action_confirmation\":{\"action_session_id\":\"asess_abc\",\"consumed\":true}}";
        CapturingClient client = new CapturingClient(stubResponse(200, body));
        AgentAdmitFilter filter = new AgentAdmitFilter(configWith(), client, r -> "write:payments");
        MockHttpServletRequest req = agentPost("/api/payments", "{\"a\":1}");
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(req, new MockHttpServletResponse(), chain);

        ActionConfirmation.Consumed consumed =
            (ActionConfirmation.Consumed) req.getAttribute("agentadmit.actionConfirmation");
        assertNotNull(consumed);
        assertEquals("asess_abc", consumed.actionSessionId());
        assertTrue(consumed.consumed());
        assertEquals(consumed,
            client.verify("ag_at_dummy_token", VerifyTelemetry.of("write:payments", "/p", "POST"))
                .actionConfirmation());
    }

    @Test
    void malformedOrUnconsumedActionConfirmationIsAbsent() throws Exception {
        String[] wireBlocks = {
            "{\"action_session_id\":\"asess_abc\",\"consumed\":\"yes\"}",  // consumed not a boolean
            "{\"action_session_id\":\"asess_abc\",\"consumed\":false}",    // staged, not consumed
            "{\"action_session_id\":17,\"consumed\":true}",                 // id not a string
            "{\"consumed\":true}",                                          // no id
            "\"asess_abc\""                                                 // not an object
        };
        for (String block : wireBlocks) {
            String body = "{\"active\":true,\"user_id\":\"u1\",\"connection_id\":\"c1\","
                + "\"scopes\":[\"write:payments\"],\"action_confirmation\":" + block + "}";
            CapturingClient client = new CapturingClient(stubResponse(200, body));
            AgentAdmitFilter filter = new AgentAdmitFilter(configWith(), client, r -> "write:payments");
            MockHttpServletRequest req = agentPost("/api/payments", "{}");

            filter.doFilter(req, new MockHttpServletResponse(), new MockFilterChain());

            assertNull(req.getAttribute("agentadmit.actionConfirmation"), "rejected block: " + block);
            assertNull(client.verify("ag_at_dummy_token", null).actionConfirmation(), "rejected block: " + block);
        }
        assertNull(ActionConfirmation.Consumed.fromVerifyData(null));
        // Absent entirely.
        CapturingClient plain = new CapturingClient(stubResponse(200, ACTIVE_BODY));
        assertNull(plain.verify("ag_at_dummy_token", null).actionConfirmation());
    }

    // -------------------------------------------------------------------------
    // The consent-first gate forwards the attestation too
    // -------------------------------------------------------------------------

    @Test
    void consentFirstTelemetryAlsoForwardsTheAttestation() {
        MockHttpServletRequest req = agentPost("/api/payments", "{}");
        req.addHeader(VerifyTelemetry.ACTION_ATTESTATION_HEADER, "asess_abc");

        VerifyTelemetry telemetry = VerifyTelemetry.forConsentFirstRequest(req, "write:payments");

        assertTrue(telemetry.consentFirst());
        assertEquals("asess_abc", telemetry.actionAttestationId());
    }

    // -------------------------------------------------------------------------
    // confirmation_declined (1.12.0): the user's explicit no, relayed typed
    // -------------------------------------------------------------------------

    @Test
    @SuppressWarnings("unchecked")
    void confirmationDeclinedIs403CarryingTheDeclineBlockAndNothingElse() throws Exception {
        CapturingClient client = new CapturingClient(stubResponse(200, CONFIRMATION_DECLINED_BODY));
        AgentAdmitFilter filter = new AgentAdmitFilter(configWith(), client, r -> "write:payments");
        MockFilterChain chain = new MockFilterChain();
        MockHttpServletResponse resp = new MockHttpServletResponse();

        filter.doFilter(agentPost("/api/payments", "{\"amount\":50}"), resp, chain);

        assertNull(chain.getRequest(), "a declined action never reaches the app");
        assertEquals(403, resp.getStatus());
        Map<String, Object> body = MAPPER.readValue(resp.getContentAsString(), Map.class);
        assertEquals("confirmation_declined", body.get("error"));
        assertTrue(((String) body.get("error_description")).contains("Do not retry"));
        Map<String, Object> declined = (Map<String, Object>) body.get("declined");
        assertEquals("asess_abc", declined.get("action_session_id"));
        assertEquals("2026-09-22T21:35:42.000Z", declined.get("declined_at"));
        assertEquals("2026-09-22T21:50:42.000Z", declined.get("hold_until"));
        assertEquals("write:payments", declined.get("scope"));
        assertEquals("Pay Alex $50", declined.get("summary"));
        assertEquals("declined", body.get("attestation_status"));
        assertTrue(((String) body.get("renewal")).contains("Only the user"));
        assertFalse(body.containsKey("confirmation"));
        assertFalse(body.containsKey("scopes"), "wire fields never leak into the denial");
        assertFalse(body.containsKey("user_id"));
    }

    @Test
    void confirmationDeclinedThrowsTheTypedDenialFromTheVerifyClient() {
        CapturingClient client = new CapturingClient(stubResponse(200, CONFIRMATION_DECLINED_BODY));

        AgentAdmitException.ConfirmationDeclinedDenial denial =
            assertThrows(AgentAdmitException.ConfirmationDeclinedDenial.class,
                () -> client.verify("ag_at_dummy_token", VerifyTelemetry.of("write:payments", "/api/payments", "POST")));

        AgentAdmitException.ActiveErrorDenial asBase = denial;
        assertFalse(asBase instanceof AgentAdmitException.ConfirmationRequiredDenial,
            "a decline is never the confirmation-required type");
        assertEquals(403, denial.getStatusCode());
        assertEquals("confirmation_declined", denial.getErrorCode());
        assertEquals("declined", denial.getAttestationStatus());
        ActionDecline d = denial.getDeclined();
        assertEquals("asess_abc", d.actionSessionId());
        assertEquals("2026-09-22T21:50:42.000Z", d.holdUntil());
        assertEquals("POST", d.method());
        assertEquals("sha256:deadbeef", d.requestDigest());
    }

    @Test
    @SuppressWarnings("unchecked")
    void malformedDeclineBlockFailsClosedWithNoBlockAndDefaultDescription() throws Exception {
        String malformed = "{\"active\":true,\"error\":\"confirmation_declined\","
            + "\"declined\":{\"action_session_id\":\"asess_abc\",\"hold_until\":7,"
            + "\"declined_at\":\"d\",\"scope\":\"s\"}}";
        CapturingClient client = new CapturingClient(stubResponse(200, malformed));
        AgentAdmitFilter filter = new AgentAdmitFilter(configWith(), client, r -> "write:payments");
        MockFilterChain chain = new MockFilterChain();
        MockHttpServletResponse resp = new MockHttpServletResponse();

        filter.doFilter(agentPost("/api/payments", "{}"), resp, chain);

        assertNull(chain.getRequest());
        assertEquals(403, resp.getStatus());
        Map<String, Object> body = MAPPER.readValue(resp.getContentAsString(), Map.class);
        assertEquals("confirmation_declined", body.get("error"));
        assertTrue(((String) body.get("error_description")).contains("unless the user asks"));
        assertFalse(body.containsKey("declined"), "a malformed decline is never relayed");

        AgentAdmitException.ActiveErrorDenial denial =
            assertThrows(AgentAdmitException.ActiveErrorDenial.class,
                () -> client.verify("ag_at_dummy_token", VerifyTelemetry.of("write:payments", "/p", "POST")));
        assertFalse(denial instanceof AgentAdmitException.ConfirmationDeclinedDenial);
    }

    @Test
    void strictParsingOfTheDeclineBlock() {
        assertNull(ActionDecline.fromVerifyData(null));
        assertNull(ActionDecline.fromVerifyData("not-an-object"));
        assertNull(ActionDecline.fromVerifyData(Map.of("action_session_id", "a", "declined_at", "d", "scope", "s")));
        ActionDecline minimal = ActionDecline.fromVerifyData(Map.of(
            "action_session_id", "a", "declined_at", "d", "hold_until", "h", "scope", "s", "method", 4));
        assertNotNull(minimal);
        assertEquals("h", minimal.holdUntil());
        assertNull(minimal.method());
        assertNull(minimal.endpoint());
        assertNull(minimal.requestDigest());
        assertNull(minimal.summary());
    }
}
