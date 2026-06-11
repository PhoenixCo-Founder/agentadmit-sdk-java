package com.agentadmit;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * TokensClient — issue, exchange, and revoke connection tokens via the
 * AgentAdmit hosted service.
 *
 * <p>The {@code duration_seconds} field on token issuance is tri-state:
 * <ul>
 *   <li>not set — omitted from the request; AgentAdmit applies its default
 *       (30 days)</li>
 *   <li>{@link IssueTokenRequestBuilder#durationUntilRevoked()} — explicit
 *       JSON {@code null}; the connection lasts until revoked</li>
 *   <li>{@link IssueTokenRequestBuilder#durationSeconds(long)} — explicit
 *       duration in seconds (60–31536000)</li>
 * </ul>
 */
@Component
public class TokensClient {

    private static final Logger logger = LoggerFactory.getLogger(TokensClient.class);

    private final AgentAdmitConfig config;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;

    /**
     * Construct the tokens client.
     *
     * @param config AgentAdmit configuration providing API key and endpoint URLs
     */
    public TokensClient(AgentAdmitConfig config) {
        this.config = config;
        this.httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();
        this.objectMapper = new ObjectMapper();
    }

    /**
     * Start building a token issuance request.
     *
     * @param userId your app's identifier for the user the connection belongs to
     * @param scopes scopes the connection grants
     * @return a builder for the remaining optional fields
     */
    public IssueTokenRequestBuilder issueToken(String userId, List<String> scopes) {
        return new IssueTokenRequestBuilder(userId, scopes);
    }

    /**
     * Exchange a single-use connection token for an access token.
     * Calls POST /api/v1/exchange — unauthenticated by design: the connection
     * token itself is the credential, so the operator API key is NOT sent.
     *
     * @param connectionToken the ag_ct_… connection token
     * @param agentLabel human-readable agent name (may be null)
     * @param agentId agent identifier (may be null)
     * @return the exchange response (access_token, scopes, connection_id, …)
     * @throws AgentAdmitException if the exchange fails
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> exchange(String connectionToken, String agentLabel, String agentId)
            throws AgentAdmitException {
        String url = config.getApiUrl().replaceAll("/$", "") + "/api/v1/exchange";
        Map<String, Object> body = new HashMap<>();
        body.put("token", connectionToken);
        if (agentLabel != null) body.put("agent_label", agentLabel);
        if (agentId != null) body.put("agent_id", agentId);
        try {
            // No Authorization header — the connection token is the credential.
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(body)))
                .timeout(Duration.ofSeconds(10))
                .build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() >= 400) {
                throw new AgentAdmitException("Token exchange failed", response.statusCode());
            }
            return objectMapper.readValue(response.body(), Map.class);
        } catch (AgentAdmitException e) {
            throw e;
        } catch (Exception e) {
            logger.error("AgentAdmit exchange failed: {}", e.getMessage());
            throw new AgentAdmitException("Token exchange failed", 502);
        }
    }

    /**
     * Revoke a connection (and its access tokens).
     * Calls POST /api/v1/revoke.
     *
     * @param connectionId the connection to revoke
     * @param reason optional human-readable reason (may be null)
     * @return the revoke response ({"ok": true, "connection_id": …, …})
     * @throws AgentAdmitException if the revocation fails
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> revoke(String connectionId, String reason) throws AgentAdmitException {
        String url = config.getApiUrl().replaceAll("/$", "") + "/api/v1/revoke";
        Map<String, Object> body = new HashMap<>();
        body.put("connection_id", connectionId);
        if (reason != null) body.put("reason", reason);
        return post(url, body, "revoke");
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> post(String url, Map<String, Object> body, String op)
            throws AgentAdmitException {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Authorization", "Bearer " + config.getApiKey())
                .header("Content-Type", "application/json")
                .header("X-App-Id", config.getAppId())
                .POST(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(body)))
                .timeout(Duration.ofSeconds(10))
                .build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() >= 400) {
                logger.error("AgentAdmit {} returned {}", op, response.statusCode());
                throw new AgentAdmitException(op + " failed", response.statusCode());
            }
            return objectMapper.readValue(response.body(), Map.class);
        } catch (AgentAdmitException e) {
            throw e;
        } catch (Exception e) {
            logger.error("AgentAdmit {} failed: {}", op, e.getMessage());
            throw new AgentAdmitException(op + " failed", 502);
        }
    }

    /**
     * Builder for POST /api/v1/apps/{app_id}/token requests. Created via
     * {@link TokensClient#issueToken(String, List)}.
     */
    public class IssueTokenRequestBuilder {
        private final Map<String, Object> body = new HashMap<>();
        private boolean durationSet = false;

        private IssueTokenRequestBuilder(String userId, List<String> scopes) {
            body.put("user_id", userId);
            body.put("scopes", scopes);
        }

        /**
         * Set the user's role granted on the connection.
         *
         * @param role the role name
         * @return this builder
         */
        public IssueTokenRequestBuilder role(String role) {
            body.put("role", role);
            return this;
        }

        /**
         * Set an explicit connection duration in seconds (60–31536000).
         *
         * @param seconds the duration
         * @return this builder
         */
        public IssueTokenRequestBuilder durationSeconds(long seconds) {
            body.put("duration_seconds", seconds);
            durationSet = true;
            return this;
        }

        /**
         * Make the connection last until the user revokes it — sends an
         * explicit JSON {@code null} for {@code duration_seconds}.
         *
         * @return this builder
         */
        public IssueTokenRequestBuilder durationUntilRevoked() {
            body.put("duration_seconds", null);
            durationSet = true;
            return this;
        }

        /**
         * Issue the connection token.
         * Calls POST /api/v1/apps/{app_id}/token. If neither duration method
         * was called, {@code duration_seconds} is omitted and AgentAdmit
         * applies its default (30 days).
         *
         * @return the issue response — {@code token} is the self-describing
         *         ag_ct_… connection token to hand to the user's agent
         * @throws AgentAdmitException if issuance fails
         */
        public Map<String, Object> send() throws AgentAdmitException {
            String url = config.getApiUrl().replaceAll("/$", "")
                + "/api/v1/apps/" + config.getAppId() + "/token";
            // A HashMap null value serializes as explicit JSON null; an absent
            // key is omitted — exactly the contract's tri-state.
            if (!durationSet) {
                body.remove("duration_seconds");
            }
            return post(url, body, "issueToken");
        }
    }
}
