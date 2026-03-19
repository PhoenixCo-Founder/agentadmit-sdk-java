package app.agentadmit;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Servlet filter that intercepts requests with ag_at_ tokens
 * and validates them via introspection.
 * 
 * Sets request attributes for downstream use:
 *   agentadmit.authType  — "agent" or null
 *   agentadmit.userId    — validated user ID
 *   agentadmit.scopes    — granted scopes
 *   agentadmit.connectionId — connection identifier
 *   agentadmit.agentLabel   — agent display name
 */
@Component
public class AgentAdmitFilter implements Filter {

    private static final Logger logger = LoggerFactory.getLogger(AgentAdmitFilter.class);
    private final AgentAdmitConfig config;
    private final IntrospectionClient introspectionClient;

    public AgentAdmitFilter(AgentAdmitConfig config, IntrospectionClient introspectionClient) {
        this.config = config;
        this.introspectionClient = introspectionClient;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpReq = (HttpServletRequest) request;
        String auth = httpReq.getHeader("Authorization");

        if (auth != null && auth.startsWith("Bearer " + config.getTokenPrefixAccess())) {
            String token = auth.substring(7); // Remove "Bearer "

            try {
                IntrospectionClient.IntrospectionResult result = introspectionClient.verify(token);

                httpReq.setAttribute("agentadmit.authType", "agent");
                httpReq.setAttribute("agentadmit.userId", result.userId());
                httpReq.setAttribute("agentadmit.scopes", result.scopes());
                httpReq.setAttribute("agentadmit.connectionId", result.connectionId());
                httpReq.setAttribute("agentadmit.agentLabel", result.agentLabel());

                logger.debug("AgentAdmit: validated agent token for user={} scopes={}", 
                    result.userId(), result.scopes());

            } catch (AgentAdmitException e) {
                HttpServletResponse httpResp = (HttpServletResponse) response;
                httpResp.setStatus(e.getStatusCode());
                httpResp.setContentType("application/json");
                httpResp.getWriter().write(
                    "{\"error\":\"" + (e.getStatusCode() == 401 ? "invalid_token" : "introspection_failed") + 
                    "\",\"error_description\":\"" + e.getMessage().replace("\"", "\\\"") + "\"}"
                );
                return;
            }
        }

        chain.doFilter(request, response);
    }
}
