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

    private String appId = "";
    private String apiKey = "";
    private String verifyUrl = "https://api.agentadmit.com/v1/verify";
    private String apiUrl = "https://api.agentadmit.com";
    private String tokenPrefixAccess = "ag_at_";
    private String tokenPrefixConnection = "ag_ct_";
    private String userLookupField = "userId";

    public String getAppId() { return appId; }
    public void setAppId(String appId) { this.appId = appId; }

    public String getApiKey() { return apiKey; }
    public void setApiKey(String apiKey) { this.apiKey = apiKey; }

    public String getVerifyUrl() { return verifyUrl; }
    public void setVerifyUrl(String verifyUrl) { this.verifyUrl = verifyUrl; }

    public String getApiUrl() { return apiUrl; }
    public void setApiUrl(String apiUrl) { this.apiUrl = apiUrl; }

    public String getTokenPrefixAccess() { return tokenPrefixAccess; }
    public void setTokenPrefixAccess(String p) { this.tokenPrefixAccess = p; }

    public String getTokenPrefixConnection() { return tokenPrefixConnection; }
    public void setTokenPrefixConnection(String p) { this.tokenPrefixConnection = p; }

    public String getUserLookupField() { return userLookupField; }
    public void setUserLookupField(String f) { this.userLookupField = f; }
}
