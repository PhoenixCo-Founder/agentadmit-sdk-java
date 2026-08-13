package com.agentadmit;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLSession;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for app-attested presence: typed forwarding at token issuance.
 *
 * Outbound (TokensClient.issueToken):
 *   - presence(...) includes the full literal-true wire object
 *     {verified: true, uv: true, method, verified_at} in the POST
 *     /api/v1/apps/{app_id}/token body, with verified_at RFC 3339 with
 *     explicit offset (the hosted contract; offset-less timestamps 400)
 *   - unset or null presence omits the field entirely (omitting the field
 *     is the only way to say "no ceremony")
 *   - an out-of-contract method (^[a-z0-9_]+$, 1-60) or a null verifiedAt
 *     throws IllegalArgumentException at construction, before any request
 */
class AppAttestedPresenceTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final OffsetDateTime CEREMONY_AT =
        OffsetDateTime.of(2026, 8, 13, 17, 0, 0, 0, ZoneOffset.UTC);

    private static HttpResponse<String> stubResponse(int status, String body) {
        HttpHeaders headers = HttpHeaders.of(Map.of(), (a, b) -> true);
        return new HttpResponse<>() {
            @Override public int statusCode() { return status; }
            @Override public HttpRequest request() { return null; }
            @Override public Optional<HttpResponse<String>> previousResponse() { return Optional.empty(); }
            @Override public HttpHeaders headers() { return headers; }
            @Override public String body() { return body; }
            @Override public Optional<SSLSession> sslSession() { return Optional.empty(); }
            @Override public URI uri() { return URI.create("https://agentadmit.example/api/v1/token"); }
            @Override public HttpClient.Version version() { return HttpClient.Version.HTTP_1_1; }
        };
    }

    private static AgentAdmitConfig configWith() {
        AgentAdmitConfig config = new AgentAdmitConfig();
        config.setApiKey("aa_test_dummy");
        config.setAppId("app_test");
        return config;
    }

    /** Captures the outbound JSON body instead of sending it. */
    private static class CapturingTokensClient extends TokensClient {
        String capturedBody;

        CapturingTokensClient() {
            super(configWith());
        }

        @Override
        HttpResponse<String> sendPost(String url, String jsonBody) {
            this.capturedBody = jsonBody;
            return stubResponse(200, "{\"token\":\"ag_ct_dummy\",\"ok\":true}");
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void presenceIsIncludedAsLiteralTrueWireObject() throws Exception {
        CapturingTokensClient client = new CapturingTokensClient();
        client.issueToken("u1", List.of("read:orders"))
            .presence(new AppAttestedPresence("my_webauthn", CEREMONY_AT))
            .send();

        Map<String, Object> body = MAPPER.readValue(client.capturedBody, Map.class);
        Map<String, Object> presence = (Map<String, Object>) body.get("presence");
        assertNotNull(presence, "presence object must be present");
        assertEquals(Boolean.TRUE, presence.get("verified"), "verified must be literal true");
        assertEquals(Boolean.TRUE, presence.get("uv"), "uv must be literal true");
        assertEquals("my_webauthn", presence.get("method"));
        assertEquals("2026-08-13T17:00:00Z", presence.get("verified_at"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void presencePreservesNonUtcOffset() throws Exception {
        CapturingTokensClient client = new CapturingTokensClient();
        client.issueToken("u1", List.of("read:orders"))
            .presence(new AppAttestedPresence(
                "my_webauthn",
                OffsetDateTime.of(2026, 8, 13, 10, 0, 0, 0, ZoneOffset.ofHours(-7))))
            .send();

        Map<String, Object> body = MAPPER.readValue(client.capturedBody, Map.class);
        Map<String, Object> presence = (Map<String, Object>) body.get("presence");
        assertEquals("2026-08-13T10:00:00-07:00", presence.get("verified_at"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void instantFactorySerializesAsUtc() throws Exception {
        CapturingTokensClient client = new CapturingTokensClient();
        client.issueToken("u1", List.of("read:orders"))
            .presence(AppAttestedPresence.of("my_webauthn", Instant.parse("2026-08-13T17:00:00Z")))
            .send();

        Map<String, Object> body = MAPPER.readValue(client.capturedBody, Map.class);
        Map<String, Object> presence = (Map<String, Object>) body.get("presence");
        assertEquals("2026-08-13T17:00:00Z", presence.get("verified_at"));
    }

    @Test
    void presenceIsOmittedWhenNotSet() throws Exception {
        CapturingTokensClient client = new CapturingTokensClient();
        client.issueToken("u1", List.of("read:orders")).send();

        Map<String, Object> body = MAPPER.readValue(client.capturedBody, Map.class);
        assertFalse(body.containsKey("presence"), "unset presence must be omitted, not null");
    }

    @Test
    void nullPresenceIsOmitted() throws Exception {
        CapturingTokensClient client = new CapturingTokensClient();
        client.issueToken("u1", List.of("read:orders")).presence(null).send();

        Map<String, Object> body = MAPPER.readValue(client.capturedBody, Map.class);
        assertFalse(body.containsKey("presence"), "null presence must be omitted, not JSON null");
    }

    @Test
    void outOfContractMethodThrowsAtConstruction() {
        for (String method : new String[]{"My_WebAuthn", "my webauthn", "my-webauthn", "", "m".repeat(61)}) {
            IllegalArgumentException ex = assertThrows(
                IllegalArgumentException.class,
                () -> new AppAttestedPresence(method, CEREMONY_AT),
                "method \"" + method + "\" must be rejected");
            assertTrue(ex.getMessage().contains("method must be"), ex.getMessage());
        }
        assertThrows(IllegalArgumentException.class,
            () -> new AppAttestedPresence(null, CEREMONY_AT));
    }

    @Test
    void nullVerifiedAtThrowsAtConstruction() {
        IllegalArgumentException ex = assertThrows(
            IllegalArgumentException.class,
            () -> new AppAttestedPresence("my_webauthn", null));
        assertTrue(ex.getMessage().contains("verifiedAt"), ex.getMessage());
        assertThrows(IllegalArgumentException.class,
            () -> AppAttestedPresence.of("my_webauthn", null));
    }
}
