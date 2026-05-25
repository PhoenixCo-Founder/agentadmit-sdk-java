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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * AlertsClient — configure and query security alerts via the AgentAdmit hosted service.
 *
 * <p>Supports 6 alert types:
 * <ul>
 *   <li>volume_spike — unusual request volume</li>
 *   <li>failed_scope_attempts — repeated scope access failures</li>
 *   <li>burst_pattern — rapid burst of requests</li>
 *   <li>stale_reactivation — dormant connection suddenly active</li>
 *   <li>new_scope_usage — agent using a scope for the first time</li>
 *   <li>revoked_connection_attempt — revoked connection trying to authenticate</li>
 * </ul>
 */
@Component
public class AlertsClient {

    private static final Logger logger = LoggerFactory.getLogger(AlertsClient.class);

    public static final String ALERT_TYPE_VOLUME_SPIKE               = "volume_spike";
    public static final String ALERT_TYPE_FAILED_SCOPE_ATTEMPTS      = "failed_scope_attempts";
    public static final String ALERT_TYPE_BURST_PATTERN              = "burst_pattern";
    public static final String ALERT_TYPE_STALE_REACTIVATION         = "stale_reactivation";
    public static final String ALERT_TYPE_NEW_SCOPE_USAGE            = "new_scope_usage";
    public static final String ALERT_TYPE_REVOKED_CONNECTION_ATTEMPT = "revoked_connection_attempt";

    private final AgentAdmitConfig config;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;

    public AlertsClient(AgentAdmitConfig config) {
        this.config = config;
        this.httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();
        this.objectMapper = new ObjectMapper();
    }

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /**
     * Configure alert thresholds for an app or connection.
     * Calls POST /api/v1/alerts.
     *
     * @param req Alert configuration parameters
     * @return Map with {"ok": true, "config": {...}}
     * @throws AgentAdmitException if the request fails
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> configureAlerts(ConfigureAlertsRequest req) throws AgentAdmitException {
        String url = config.getApiUrl().replaceAll("/$", "") + "/api/v1/alerts";
        try {
            String body = objectMapper.writeValueAsString(req.toMap());
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Authorization", "Bearer " + config.getApiKey())
                .header("Content-Type", "application/json")
                .header("X-App-Id", config.getAppId())
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .timeout(Duration.ofSeconds(10))
                .build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            checkStatus(response, "configureAlerts");
            return objectMapper.readValue(response.body(), Map.class);
        } catch (AgentAdmitException e) {
            throw e;
        } catch (Exception e) {
            logger.error("AgentAdmit configureAlerts failed: {}", e.getMessage());
            throw new AgentAdmitException("configureAlerts failed: " + e.getMessage(), 502);
        }
    }

    /**
     * List alert events for an app.
     * Calls GET /api/v1/alerts.
     *
     * @param appId       Your AgentAdmit application ID
     * @param connectionId Optional — filter by connection (may be null)
     * @param alertType   Optional — filter by alert type (may be null)
     * @param limit       Max events to return (pass 0 for default 50)
     * @param offset      Pagination offset
     * @return Map with {"events": [...], "total": int, "limit": int, "offset": int}
     * @throws AgentAdmitException if the request fails
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> listAlerts(
        String appId,
        String connectionId,
        String alertType,
        int limit,
        int offset
    ) throws AgentAdmitException {
        StringBuilder url = new StringBuilder(
            config.getApiUrl().replaceAll("/$", "") + "/api/v1/alerts?app_id=" + appId
        );
        if (connectionId != null && !connectionId.isEmpty()) {
            url.append("&connection_id=").append(connectionId);
        }
        if (alertType != null && !alertType.isEmpty()) {
            url.append("&alert_type=").append(alertType);
        }
        url.append("&limit=").append(limit > 0 ? limit : 50);
        url.append("&offset=").append(offset);

        try {
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url.toString()))
                .header("Authorization", "Bearer " + config.getApiKey())
                .header("X-App-Id", config.getAppId())
                .GET()
                .timeout(Duration.ofSeconds(10))
                .build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            checkStatus(response, "listAlerts");
            return objectMapper.readValue(response.body(), Map.class);
        } catch (AgentAdmitException e) {
            throw e;
        } catch (Exception e) {
            logger.error("AgentAdmit listAlerts failed: {}", e.getMessage());
            throw new AgentAdmitException("listAlerts failed: " + e.getMessage(), 502);
        }
    }

    /**
     * Convenience overload for listAlerts with default limit/offset.
     */
    public Map<String, Object> listAlerts(String appId, String connectionId, String alertType)
        throws AgentAdmitException {
        return listAlerts(appId, connectionId, alertType, 50, 0);
    }

    /**
     * Get the current alert configuration for an app.
     * Calls GET /api/v1/alerts/config.
     *
     * @param appId        Your AgentAdmit application ID
     * @param connectionId Optional — filter by connection (may be null)
     * @return Map with {"app_id", "app_level", "connection_overrides", "alert_types"}
     * @throws AgentAdmitException if the request fails
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> getAlertConfig(String appId, String connectionId)
        throws AgentAdmitException {
        StringBuilder url = new StringBuilder(
            config.getApiUrl().replaceAll("/$", "") + "/api/v1/alerts/config?app_id=" + appId
        );
        if (connectionId != null && !connectionId.isEmpty()) {
            url.append("&connection_id=").append(connectionId);
        }

        try {
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url.toString()))
                .header("Authorization", "Bearer " + config.getApiKey())
                .header("X-App-Id", config.getAppId())
                .GET()
                .timeout(Duration.ofSeconds(10))
                .build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            checkStatus(response, "getAlertConfig");
            return objectMapper.readValue(response.body(), Map.class);
        } catch (AgentAdmitException e) {
            throw e;
        } catch (Exception e) {
            logger.error("AgentAdmit getAlertConfig failed: {}", e.getMessage());
            throw new AgentAdmitException("getAlertConfig failed: " + e.getMessage(), 502);
        }
    }

    /** Convenience overload with no connectionId filter. */
    public Map<String, Object> getAlertConfig(String appId) throws AgentAdmitException {
        return getAlertConfig(appId, null);
    }

    // -------------------------------------------------------------------------
    // Inner classes
    // -------------------------------------------------------------------------

    /**
     * Request body for configureAlerts.
     * Use the builder: ConfigureAlertsRequest.builder().appId(...).alertType(...).build()
     */
    public static class ConfigureAlertsRequest {
        private final String appId;
        private final String alertType;
        private final String connectionId;
        private final Boolean enabled;
        private final Double thresholdValue;
        private final Integer thresholdWindowMinutes;
        private final Double thresholdRatePerMinute;
        private final Integer staleDays;
        private final Boolean killSwitchEnabled;
        private final Double killSwitchThresholdValue;
        private final Integer killSwitchThresholdWindowMinutes;

        private ConfigureAlertsRequest(Builder b) {
            this.appId = b.appId;
            this.alertType = b.alertType;
            this.connectionId = b.connectionId;
            this.enabled = b.enabled;
            this.thresholdValue = b.thresholdValue;
            this.thresholdWindowMinutes = b.thresholdWindowMinutes;
            this.thresholdRatePerMinute = b.thresholdRatePerMinute;
            this.staleDays = b.staleDays;
            this.killSwitchEnabled = b.killSwitchEnabled;
            this.killSwitchThresholdValue = b.killSwitchThresholdValue;
            this.killSwitchThresholdWindowMinutes = b.killSwitchThresholdWindowMinutes;
        }

        public static Builder builder() { return new Builder(); }

        public Map<String, Object> toMap() {
            Map<String, Object> m = new HashMap<>();
            m.put("app_id", appId);
            m.put("alert_type", alertType);
            if (connectionId != null)                  m.put("connection_id", connectionId);
            if (enabled != null)                       m.put("enabled", enabled);
            if (thresholdValue != null)                m.put("threshold_value", thresholdValue);
            if (thresholdWindowMinutes != null)        m.put("threshold_window_minutes", thresholdWindowMinutes);
            if (thresholdRatePerMinute != null)        m.put("threshold_rate_per_minute", thresholdRatePerMinute);
            if (staleDays != null)                     m.put("stale_days", staleDays);
            if (killSwitchEnabled != null)             m.put("kill_switch_enabled", killSwitchEnabled);
            if (killSwitchThresholdValue != null)      m.put("kill_switch_threshold_value", killSwitchThresholdValue);
            if (killSwitchThresholdWindowMinutes != null) m.put("kill_switch_threshold_window_minutes", killSwitchThresholdWindowMinutes);
            return m;
        }

        public static class Builder {
            private String appId;
            private String alertType;
            private String connectionId;
            private Boolean enabled;
            private Double thresholdValue;
            private Integer thresholdWindowMinutes;
            private Double thresholdRatePerMinute;
            private Integer staleDays;
            private Boolean killSwitchEnabled;
            private Double killSwitchThresholdValue;
            private Integer killSwitchThresholdWindowMinutes;

            public Builder appId(String v)                             { this.appId = v; return this; }
            public Builder alertType(String v)                         { this.alertType = v; return this; }
            public Builder connectionId(String v)                      { this.connectionId = v; return this; }
            public Builder enabled(boolean v)                          { this.enabled = v; return this; }
            public Builder thresholdValue(double v)                    { this.thresholdValue = v; return this; }
            public Builder thresholdWindowMinutes(int v)               { this.thresholdWindowMinutes = v; return this; }
            public Builder thresholdRatePerMinute(double v)            { this.thresholdRatePerMinute = v; return this; }
            public Builder staleDays(int v)                            { this.staleDays = v; return this; }
            public Builder killSwitchEnabled(boolean v)                { this.killSwitchEnabled = v; return this; }
            public Builder killSwitchThresholdValue(double v)          { this.killSwitchThresholdValue = v; return this; }
            public Builder killSwitchThresholdWindowMinutes(int v)     { this.killSwitchThresholdWindowMinutes = v; return this; }

            public ConfigureAlertsRequest build() {
                if (appId == null || alertType == null) {
                    throw new IllegalStateException("appId and alertType are required");
                }
                return new ConfigureAlertsRequest(this);
            }
        }
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private void checkStatus(HttpResponse<String> response, String operation) throws AgentAdmitException {
        int status = response.statusCode();
        if (status >= 400) {
            logger.error("AgentAdmit {} failed with status {}: {}", operation, status, response.body());
            throw new AgentAdmitException(operation + " failed with HTTP " + status, status);
        }
    }
}
