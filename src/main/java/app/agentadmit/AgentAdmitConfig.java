package app.agentadmit;

/*
 * IMPORTANT: AgentAdmit uses MANDATORY hosted introspection.
 * All token validation goes through api.agentadmit.com.
 * There is no self-hosted mode. No local JWT validation. No bypass.
 * This is required for security, audit logging, and scope enforcement.
 */

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * AgentAdmit configuration loaded from application.yml/properties.
 * 
 * agentadmit:
 *   app-id: "app_abc123"
 *   api-key: "aa_live_xxxx"
 *   verify-url: "https://api.agentadmit.com/v1/verify"
 *   api-url: "https://api.agentadmit.com"
 *   user-lookup-field: "userId"
 */
@Component
@ConfigurationProperties(prefix = "agentadmit")
public class AgentAdmitConfig {

    /** Create a new configuration instance with default values. */
    public AgentAdmitConfig() {}

    /** Your AgentAdmit application ID (e.g. {@code "app_abc123"}). */
    private String appId = "";

    /** Your AgentAdmit API key (e.g. {@code "aa_live_xxxx"}). */
    private String apiKey = "";

    /** Token verification endpoint URL. */
    private String verifyUrl = "https://api.agentadmit.com/v1/verify";

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
     * Set the API key.
     * @param apiKey your AgentAdmit API key
     */
    public void setApiKey(String apiKey) { this.apiKey = apiKey; }

    /**
     * Get the token verification endpoint URL.
     * @return the verify URL
     */
    public String getVerifyUrl() { return verifyUrl; }
    /**
     * Set the token verification endpoint URL.
     * @param verifyUrl the verify URL
     */
    public void setVerifyUrl(String verifyUrl) { this.verifyUrl = verifyUrl; }

    /**
     * Get the base API URL.
     * @return the API base URL
     */
    public String getApiUrl() { return apiUrl; }
    /**
     * Set the base API URL.
     * @param apiUrl the API base URL
     */
    public void setApiUrl(String apiUrl) { this.apiUrl = apiUrl; }

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
