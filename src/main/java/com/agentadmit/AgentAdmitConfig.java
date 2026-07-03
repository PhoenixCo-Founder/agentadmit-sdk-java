package com.agentadmit;

/*
 * IMPORTANT: AgentAdmit uses MANDATORY hosted introspection.
 * All token validation goes through api.agentadmit.com.
 * There is no self-hosted mode. No local JWT validation. No bypass.
 * This is required for security, audit logging, and scope enforcement.
 */

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * AgentAdmit configuration loaded from application.yml/properties.
 *
 * <p>Registered as a Spring bean via
 * {@code @EnableConfigurationProperties(AgentAdmitConfig.class)} in
 * {@link AgentAdmitAutoConfiguration}. Do not add {@code @Component} here;
 * let the auto-configuration own registration so there is exactly one bean.
 *
 * agentadmit:
 *   app-id: "app_abc123"
 *   api-key: "aa_live_xxxx"
 *   verify-url: "https://api.agentadmit.com/api/v1/verify"
 *   api-url: "https://api.agentadmit.com"
 *   user-lookup-field: "userId"
 */
@ConfigurationProperties(prefix = "agentadmit")
public class AgentAdmitConfig {

    /** Create a new configuration instance with default values. */
    public AgentAdmitConfig() {}

    /** Your AgentAdmit application ID (e.g. {@code "app_abc123"}). */
    private String appId = "";

    /** Your AgentAdmit API key (e.g. {@code "aa_live_xxxx"}). */
    private String apiKey = "";

    /** Token verification endpoint URL. */
    private String verifyUrl = "https://api.agentadmit.com/api/v1/verify";

    /** Base API URL for AgentAdmit services. */
    private String apiUrl = "https://api.agentadmit.com";

    /** Prefix identifying AgentAdmit access tokens. */
    private String tokenPrefixAccess = "ag_at_";

    /** Prefix identifying AgentAdmit connection tokens. */
    private String tokenPrefixConnection = "ag_ct_";

    /** Request attribute or claim used to identify the end user. */
    private String userLookupField = "userId";

    /**
     * Get the configured application ID.
     * @return the application ID
     */
    public String getAppId() { return appId; }
    /**
     * Set the application ID.
     * @param appId your AgentAdmit application ID
     */
    public void setAppId(String appId) { this.appId = appId; }

    /**
     * Get the configured API key.
     * @return the API key
     */
    public String getApiKey() { return apiKey; }
    /**
     * Set the API key. Must start with {@code aa_test_} or {@code aa_live_}.
     * @param apiKey your AgentAdmit API key
     * @throws IllegalArgumentException if a non-empty key has the wrong prefix
     */
    public void setApiKey(String apiKey) {
        if (apiKey != null && !apiKey.isEmpty()
                && !apiKey.startsWith("aa_test_") && !apiKey.startsWith("aa_live_")) {
            // Never echo the key itself.
            throw new IllegalArgumentException("apiKey must start with 'aa_test_' or 'aa_live_'");
        }
        this.apiKey = apiKey;
    }

    /**
     * Get the token verification endpoint URL.
     * @return the verify URL
     */
    public String getVerifyUrl() { return verifyUrl; }
    /**
     * Set the token verification endpoint URL.
     * Non-HTTPS URLs are rejected unless the host is {@code localhost},
     * {@code 127.0.0.1}, or {@code [::1]} (plain HTTP on loopback is allowed
     * for local development).
     *
     * @param verifyUrl the verify URL
     * @throws IllegalArgumentException if the URL is not HTTPS (except on loopback)
     */
    public void setVerifyUrl(String verifyUrl) {
        requireHttpsOrLoopback(verifyUrl, "verifyUrl");
        this.verifyUrl = verifyUrl;
    }

    /**
     * Get the base API URL.
     * @return the API base URL
     */
    public String getApiUrl() { return apiUrl; }
    /**
     * Set the base API URL.
     * Non-HTTPS URLs are rejected unless the host is {@code localhost},
     * {@code 127.0.0.1}, or {@code [::1]} (plain HTTP on loopback is allowed
     * for local development).
     *
     * @param apiUrl the API base URL
     * @throws IllegalArgumentException if the URL is not HTTPS (except on loopback)
     */
    public void setApiUrl(String apiUrl) {
        requireHttpsOrLoopback(apiUrl, "apiUrl");
        this.apiUrl = apiUrl;
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /**
     * Require that a URL is HTTPS, or HTTP only when the host is a loopback
     * address ({@code localhost}, {@code 127.0.0.1}, or {@code [::1]}).
     *
     * @param url   the URL to validate
     * @param field the configuration field name (for the error message)
     * @throws IllegalArgumentException if the URL scheme is http for a non-loopback host
     */
    private static void requireHttpsOrLoopback(String url, String field) {
        if (url == null || url.isEmpty()) {
            return; // let other validators handle blank values
        }
        if (url.startsWith("https://")) {
            return; // always allowed
        }
        if (url.startsWith("http://")) {
            // Only loopback hosts may use plain HTTP.
            String lower = url.toLowerCase();
            if (lower.startsWith("http://localhost")
                    || lower.startsWith("http://127.0.0.1")
                    || lower.startsWith("http://[::1]")) {
                return;
            }
            throw new IllegalArgumentException(
                "AgentAdmit configuration error: " + field
                + " must use HTTPS. Plain HTTP is only permitted for loopback addresses"
                + " (localhost, 127.0.0.1, [::1]). Got: " + url
            );
        }
        // Any other scheme (ftp://, custom://, etc.) is also rejected.
        throw new IllegalArgumentException(
            "AgentAdmit configuration error: " + field
            + " must be an HTTPS URL. Got: " + url
        );
    }

    /**
     * Get the access token prefix.
     * @return the access token prefix
     */
    public String getTokenPrefixAccess() { return tokenPrefixAccess; }
    /**
     * Set the access token prefix.
     * @param p the access token prefix
     */
    public void setTokenPrefixAccess(String p) { this.tokenPrefixAccess = p; }

    /**
     * Get the connection token prefix.
     * @return the connection token prefix
     */
    public String getTokenPrefixConnection() { return tokenPrefixConnection; }
    /**
     * Set the connection token prefix.
     * @param p the connection token prefix
     */
    public void setTokenPrefixConnection(String p) { this.tokenPrefixConnection = p; }

    /**
     * Get the user lookup field name.
     * @return the user lookup field name
     */
    public String getUserLookupField() { return userLookupField; }
    /**
     * Set the user lookup field name.
     * @param f the user lookup field name
     */
    public void setUserLookupField(String f) { this.userLookupField = f; }

    /** Max retries on HTTP 429 before throwing RateLimitError. Default: 3. */
    private int maxRetries = 3;

    /**
     * Get max retries on HTTP 429.
     * @return max retry count
     */
    public int getMaxRetries() { return maxRetries; }
    /**
     * Set max retries on HTTP 429.
     * @param maxRetries max retry count
     */
    public void setMaxRetries(int maxRetries) { this.maxRetries = maxRetries; }
}
