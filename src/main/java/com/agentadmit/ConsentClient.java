package com.agentadmit;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

/**
 * Consent Ledger client — hosted caller-identity consent verdicts.
 *
 * <p>External agents get their verdict inline in the verify response
 * ({@link IntrospectionClient.IntrospectionResult#consent()}). The two
 * token-less caller classes (human sessions and your app's own in-app AI)
 * ask {@link #checkConsent(String, String, String)}.
 *
 * <p>Consent is orthogonal to token revocation: on a denied verdict your app
 * returns its own 403; nothing is revoked. Every evaluation is appended to
 * the exportable consent trail.
 */
public class ConsentClient {

    /** Human users reaching their own data through the app's normal UI. */
    public static final String CALLER_CLASS_HUMAN_SESSION = "human_session";
    /** The app's own AI features reading user data on the user's behalf. */
    public static final String CALLER_CLASS_IN_APP_AI = "in_app_ai";
    /** Third-party AI agents connected through AgentAdmit. */
    public static final String CALLER_CLASS_EXTERNAL_AGENT = "external_agent";

    private static final Logger logger = LoggerFactory.getLogger(ConsentClient.class);

    private final AgentAdmitConfig config;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;

    /**
     * Construct the consent client.
     *
     * @param config AgentAdmit configuration providing API key and endpoint URLs
     */
    public ConsentClient(AgentAdmitConfig config) {
        this.config = config;
        this.httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();
        this.objectMapper = new ObjectMapper();
    }

    /**
     * Ask the Consent Ledger whether a caller class may act on a user's data.
     * Calls {@code POST /api/v1/consent/check} on the AgentAdmit hosted service.
     *
     * @param appUserId   your app's identifier for the data owner
     * @param callerClass one of the CALLER_CLASS_* constants
     * @param scopeGroup  optional finer-than-class consent group; may be null
     * @return the verdict map: {@code granted} (Boolean), {@code caller_class},
     *         {@code scope_group}, {@code source} (which layer resolved it),
     *         {@code evaluated_at}
     * @throws AgentAdmitException if the request is rejected or the service is unreachable
     */
    public Map<String, Object> checkConsent(String appUserId, String callerClass, String scopeGroup)
            throws AgentAdmitException {
        if (!CALLER_CLASS_HUMAN_SESSION.equals(callerClass)
                && !CALLER_CLASS_IN_APP_AI.equals(callerClass)
                && !CALLER_CLASS_EXTERNAL_AGENT.equals(callerClass)) {
            throw new AgentAdmitException(
                "callerClass must be one of human_session, in_app_ai, external_agent", 400);
        }

        Map<String, Object> body = new HashMap<>();
        body.put("app_user_id", appUserId);
        body.put("caller_class", callerClass);
        if (scopeGroup != null) {
            body.put("scope_group", scopeGroup);
        }

        String url = config.getApiUrl().replaceAll("/$", "") + "/api/v1/consent/check";
        try {
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Authorization", "Bearer " + config.getApiKey())
                .header("Content-Type", "application/json")
                .header("X-App-Id", config.getAppId())
                .POST(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(body)))
                .timeout(Duration.ofSeconds(10))
                .build();
            HttpResponse<String> response = sendConsentRequest(request);
            if (response.statusCode() >= 400) {
                logger.error("AgentAdmit checkConsent returned {}", response.statusCode());
                throw new AgentAdmitException("checkConsent failed", response.statusCode());
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> verdict = objectMapper.readValue(response.body(), Map.class);
            return verdict;
        } catch (AgentAdmitException e) {
            throw e;
        } catch (Exception e) {
            logger.error("AgentAdmit checkConsent failed: {}", e.getMessage());
            throw new AgentAdmitException("checkConsent failed", 502);
        }
    }

    /** Package-visible so tests can stub the hosted-service response. */
    HttpResponse<String> sendConsentRequest(HttpRequest request) throws Exception {
        return httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    }
}
