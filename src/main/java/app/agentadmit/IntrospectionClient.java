package app.agentadmit;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;

/**
 * Mandatory introspection client — validates tokens via AgentAdmit hosted service.
 * No local JWT decode. Every verification call goes through AgentAdmit.
 */
@Component
public class IntrospectionClient {

    private static final Logger logger = LoggerFactory.getLogger(IntrospectionClient.class);
    private final AgentAdmitConfig config;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;

    public IntrospectionClient(AgentAdmitConfig config) {
        this.config = config;
        this.httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();
        this.objectMapper = new ObjectMapper();
    }

    /**
     * Validate an ag_at_ token via introspection.
     *
     * @param token The full token including ag_at_ prefix
     * @return IntrospectionResult with scopes, user_id, connection_id
     * @throws AgentAdmitException if validation fails
     */
    public IntrospectionResult verify(String token) throws AgentAdmitException {
        if (!token.startsWith(config.getTokenPrefixAccess())) {
            throw new AgentAdmitException("Not an AgentAdmit access token", 401);
        }

        try {
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(config.getVerifyUrl()))
                .header("Authorization", "Bearer " + token)
                .header("X-App-Id", config.getAppId())
                .header("X-Api-Key", config.getApiKey())
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.noBody())
                .timeout(Duration.ofSeconds(5))
                .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 401) {
                Map<String, Object> errData = objectMapper.readValue(response.body(), Map.class);
                String desc = (String) errData.getOrDefault("error_description", "Token validation failed");
                throw new AgentAdmitException(desc, 401);
            }

            if (response.statusCode() != 200) {
                throw new AgentAdmitException("Verification service returned " + response.statusCode(), 502);
            }

            Map<String, Object> data = objectMapper.readValue(response.body(), Map.class);

            String userId = (String) data.get("user_id");
            String connectionId = (String) data.get("connection_id");
            List<String> scopes = (List<String>) data.getOrDefault("scopes", List.of());
            String agentLabel = (String) data.getOrDefault("agent_label", "Unknown Agent");

            if (userId == null) {
                throw new AgentAdmitException("Introspection returned no user", 401);
            }

            return new IntrospectionResult(userId, connectionId, scopes, agentLabel);

        } catch (AgentAdmitException e) {
            throw e;
        } catch (Exception e) {
            logger.error("AgentAdmit introspection failed: {}", e.getMessage());
            throw new AgentAdmitException("Introspection failed: " + e.getMessage(), 502);
        }
    }

    /**
     * Result of a successful introspection call.
     */
    public record IntrospectionResult(
        String userId,
        String connectionId,
        List<String> scopes,
        String agentLabel
    ) {
        public boolean hasScope(String scope) {
            return scopes.contains(scope);
        }
    }
}
