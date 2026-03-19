package app.agentadmit;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.List;

/**
 * AOP aspect that intercepts methods annotated with @RequireScope or @RequireScopeIfAgent
 * and enforces scope requirements.
 */
@Aspect
@Component
public class ScopeEnforcementAspect {

    @Around("@annotation(requireScope)")
    public Object enforceScope(ProceedingJoinPoint joinPoint, RequireScope requireScope) throws Throwable {
        HttpServletRequest request = getCurrentRequest();
        String authType = (String) request.getAttribute("agentadmit.authType");

        if (!"agent".equals(authType)) {
            // No agent token — return 401
            HttpServletResponse response = getCurrentResponse();
            response.setStatus(401);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\":\"invalid_token\",\"error_description\":\"AgentAdmit token required\"}");
            return null;
        }

        return checkScopeAndProceed(joinPoint, requireScope.value(), request);
    }

    @Around("@annotation(requireScopeIfAgent)")
    public Object enforceScopeIfAgent(ProceedingJoinPoint joinPoint, RequireScopeIfAgent requireScopeIfAgent) throws Throwable {
        HttpServletRequest request = getCurrentRequest();
        String authType = (String) request.getAttribute("agentadmit.authType");

        if (!"agent".equals(authType)) {
            // Not an agent — pass through without scope enforcement
            return joinPoint.proceed();
        }

        return checkScopeAndProceed(joinPoint, requireScopeIfAgent.value(), request);
    }

    @SuppressWarnings("unchecked")
    private Object checkScopeAndProceed(ProceedingJoinPoint joinPoint, String requiredScope, HttpServletRequest request) throws Throwable {
        List<String> scopes = (List<String>) request.getAttribute("agentadmit.scopes");

        if (scopes == null || !scopes.contains(requiredScope)) {
            HttpServletResponse response = getCurrentResponse();
            response.setStatus(403);
            response.setContentType("application/json");
            response.getWriter().write(
                "{\"error\":\"insufficient_scope\"," +
                "\"required_scope\":\"" + requiredScope + "\"," +
                "\"granted_scopes\":" + (scopes != null ? scopes.toString() : "[]") + "," +
                "\"message\":\"This action requires '" + requiredScope + "' scope.\"}"
            );
            return null;
        }

        return joinPoint.proceed();
    }

    private HttpServletRequest getCurrentRequest() {
        ServletRequestAttributes attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (attrs == null) throw new IllegalStateException("No request context");
        return attrs.getRequest();
    }

    private HttpServletResponse getCurrentResponse() {
        ServletRequestAttributes attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (attrs == null) throw new IllegalStateException("No request context");
        return attrs.getResponse();
    }
}
