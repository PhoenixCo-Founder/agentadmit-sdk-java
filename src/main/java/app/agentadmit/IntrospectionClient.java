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
import java.util.Optional;
import java.util.concurrent.ThreadLocalRandom;

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
     * <p>Automatically retries on HTTP 429 with exponential backoff + jitter.
     * Throws {@link AgentAdmitException.RateLimitError} when retries are exhausted.
     *
     * @param token The full token including ag_at_ prefix
     * @return IntrospectionResult with scopes, user_id, connection_id
     * @throws AgentAdmitException if validation fails
     * @throws AgentAdmitException.RateLimitError if rate-limited and retries exhausted
     */
    public IntrospectionResult verify(String token) throws AgentAdmitException {
        if (!token.startsWith(config.getTokenPrefixAccess())) {
            throw new AgentAdmitException("Not an AgentAdmit access token", 401);
        }

        int maxRetries = config.getMaxRetries();
        long delayMs = 1_000L; // initial backoff: 1 second

        for (int attempt = 0; attempt <= maxRetries; attempt++) {
            HttpResponse<String> response = sendIntrospectionRequest(token);

            int status = response.statusCode();

            if (status == 429) {
                // Parse rate-limit headers
                double retryAfter  = parseDoubleHeader(response, "Retry-After");
                int    rlLimit     = parseIntHeader(response,    "X-RateLimit-Limit");
                int    rlRemaining = parseIntHeader(response,    "X-RateLimit-Remaining");
                long   rlReset     = parseLongHeader(response,   "X-RateLimit-Reset");

                if (attempt >= maxRetries) {
                    throw new AgentAdmitException.RateLimitError(
                        "AgentAdmit rate limit exceeded. Max retries (" + maxRetries + ") exhausted.",
                        retryAfter, rlLimit, rlRemaining, rlReset
                    );
                }

                // Compute wait: honor Retry-After header, or use exponential backoff
                long waitMs = retryAfter >= 0
                    ? (long)(retryAfter * 1000)
                    : Math.min(delayMs, 30_000L);
                long jitterMs = ThreadLocalRandom.current().nextLong(0, 500);
                long totalWaitMs = waitMs + jitterMs;

                logger.warn("AgentAdmit introspection rate-limited (attempt {}/{}). Retrying in {}ms.",
                    attempt + 1, maxRetries, totalWaitMs);

                try {
                    Thread.sleep(totalWaitMs);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    throw new AgentAdmitException("Interrupted while retrying after rate limit", 429);
                }

                delayMs = Math.min(delayMs * 2, 30_000L);
                continue;
            }

            // Non-429 response — process normally
            try {
                if (status == 401) {
                    Map<String, Object> errData = objectMapper.readValue(response.body(), Map.class);
                    String desc = (String) errData.getOrDefault("error_description", "Token validation failed");
                    throw new AgentAdmitException(desc, 401);
                }

                if (status != 200) {
                    throw new AgentAdmitException("Verification service returned " + status, 502);
                }

                Map<String, Object> data = objectMapper.readValue(response.body(), Map.class);

                // Check active flag (RFC 7662 introspection pattern).
                // The verify endpoint returns {active: false} with HTTP 200 for invalid/
                // expired/revoked tokens. Without this check, we'd read empty scopes.
                Boolean active = (Boolean) data.get("active");
                if (active == null || !active) {
                    String reason = (String) data.getOrDefault("error", "invalid_token");
                    throw new AgentAdmitException("Token is not active: " + reason, 401);
                }

                String userId = (String) data.get("user_id");
                String connectionId = (String) data.get("connection_id");
                @SuppressWarnings("unchecked")
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

        // Should never be reached
        throw new AgentAdmitException("Unexpected exit from retry loop", 500);
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private HttpResponse<String> sendIntrospectionRequest(String token) throws AgentAdmitException {
        try {
            String body = "{\"token\":\"" + token + "\"}";
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(config.getVerifyUrl()))
                .header("Authorization", "Bearer " + config.getApiKey())
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .timeout(Duration.ofSeconds(5))
                .build();
            return httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (Exception e) {
            logger.error("AgentAdmit introspection network error: {}", e.getMessage());
            throw new AgentAdmitException("Introspection failed: " + e.getMessage(), 502);
        }
    }

    /** Returns the header value as a double, or -1 if absent/invalid. */
    private double parseDoubleHeader(HttpResponse<?> response, String name) {
        return response.headers().firstValue(name).map(v -> {
            try { return Double.parseDouble(v); } catch (NumberFormatException e) { return -1.0; }
        }).orElse(-1.0);
    }

    /** Returns the header value as an int, or -1 if absent/invalid. */
    private int parseIntHeader(HttpResponse<?> response, String name) {
        return response.headers().firstValue(name).map(v -> {
            try { return Integer.parseInt(v); } catch (NumberFormatException e) { return -1; }
        }).orElse(-1);
    }

    /** Returns the header value as a long, or -1 if absent/invalid. */
    private long parseLongHeader(HttpResponse<?> response, String name) {
        return response.headers().firstValue(name).map(v -> {
            try { return Long.parseLong(v); } catch (NumberFormatException e) { return -1L; }
        }).orElse(-1L);
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
