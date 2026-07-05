package com.agentadmit;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for M5: RFC 7235 case-insensitive Bearer scheme matching.
 *
 * The "Bearer" scheme token in Authorization headers is case-insensitive per
 * RFC 7235; the ag_at_ token prefix that follows stays case-sensitive.
 */
class BearerCaseInsensitiveTest {

    /** Minimal IntrospectionClient stub that always returns a successful result. */
    private static class AlwaysValidClient extends IntrospectionClient {
        AlwaysValidClient() {
            super(defaultConfig());
        }

        private static AgentAdmitConfig defaultConfig() {
            AgentAdmitConfig cfg = new AgentAdmitConfig();
            cfg.setApiKey("aa_test_dummy");
            return cfg;
        }

        @Override
        public IntrospectionResult verify(String token) {
            return new IntrospectionResult("user_1", "conn_1", List.of("read:orders"),
                "TestAgent", null, null, null, null, 0L, null, null);
        }
    }

    /** Attribute-capturing mock HttpServletRequest. */
    private static class FakeRequest implements HttpServletRequest {
        private final String authHeader;
        private final Map<String, Object> attributes = new HashMap<>();

        FakeRequest(String authHeader) { this.authHeader = authHeader; }

        @Override public String getHeader(String name) {
            return "Authorization".equalsIgnoreCase(name) ? authHeader : null;
        }
        @Override public void setAttribute(String name, Object o) { attributes.put(name, o); }
        @Override public Object getAttribute(String name) { return attributes.get(name); }

        // Minimal no-op implementations for unused methods
        @Override public String getAuthType() { return null; }
        @Override public jakarta.servlet.http.Cookie[] getCookies() { return null; }
        @Override public long getDateHeader(String name) { return -1; }
        @Override public java.util.Enumeration<String> getHeaders(String name) { return java.util.Collections.emptyEnumeration(); }
        @Override public java.util.Enumeration<String> getHeaderNames() { return java.util.Collections.emptyEnumeration(); }
        @Override public int getIntHeader(String name) { return -1; }
        @Override public String getMethod() { return "GET"; }
        @Override public String getPathInfo() { return null; }
        @Override public String getPathTranslated() { return null; }
        @Override public String getContextPath() { return ""; }
        @Override public String getQueryString() { return null; }
        @Override public String getRemoteUser() { return null; }
        @Override public boolean isUserInRole(String role) { return false; }
        @Override public java.security.Principal getUserPrincipal() { return null; }
        @Override public String getRequestedSessionId() { return null; }
        @Override public String getRequestURI() { return "/api/test"; }
        @Override public StringBuffer getRequestURL() { return new StringBuffer("http://localhost/api/test"); }
        @Override public String getServletPath() { return "/api/test"; }
        @Override public jakarta.servlet.http.HttpSession getSession(boolean create) { return null; }
        @Override public jakarta.servlet.http.HttpSession getSession() { return null; }
        @Override public String changeSessionId() { return null; }
        @Override public boolean isRequestedSessionIdValid() { return false; }
        @Override public boolean isRequestedSessionIdFromCookie() { return false; }
        @Override public boolean isRequestedSessionIdFromURL() { return false; }
        @Override public boolean authenticate(HttpServletResponse response) { return false; }
        @Override public void login(String username, String password) {}
        @Override public void logout() {}
        @Override public java.util.Collection<jakarta.servlet.http.Part> getParts() { return List.of(); }
        @Override public jakarta.servlet.http.Part getPart(String name) { return null; }
        @Override public <T extends jakarta.servlet.http.HttpUpgradeHandler> T upgrade(Class<T> handlerClass) { return null; }
        @Override public java.util.Enumeration<String> getAttributeNames() { return java.util.Collections.emptyEnumeration(); }
        @Override public String getCharacterEncoding() { return "UTF-8"; }
        @Override public void setCharacterEncoding(String env) {}
        @Override public int getContentLength() { return 0; }
        @Override public long getContentLengthLong() { return 0L; }
        @Override public String getContentType() { return null; }
        @Override public jakarta.servlet.ServletInputStream getInputStream() { return null; }
        @Override public String getParameter(String name) { return null; }
        @Override public java.util.Enumeration<String> getParameterNames() { return java.util.Collections.emptyEnumeration(); }
        @Override public String[] getParameterValues(String name) { return null; }
        @Override public java.util.Map<String, String[]> getParameterMap() { return Map.of(); }
        @Override public String getProtocol() { return "HTTP/1.1"; }
        @Override public String getScheme() { return "http"; }
        @Override public String getServerName() { return "localhost"; }
        @Override public int getServerPort() { return 8080; }
        @Override public java.io.BufferedReader getReader() { return null; }
        @Override public String getRemoteAddr() { return "127.0.0.1"; }
        @Override public String getRemoteHost() { return "localhost"; }
        @Override public void removeAttribute(String name) { attributes.remove(name); }
        @Override public java.util.Locale getLocale() { return java.util.Locale.getDefault(); }
        @Override public java.util.Enumeration<java.util.Locale> getLocales() { return java.util.Collections.emptyEnumeration(); }
        @Override public boolean isSecure() { return false; }
        @Override public jakarta.servlet.RequestDispatcher getRequestDispatcher(String path) { return null; }
        @Override public int getRemotePort() { return 0; }
        @Override public String getLocalName() { return "localhost"; }
        @Override public String getLocalAddr() { return "127.0.0.1"; }
        @Override public int getLocalPort() { return 8080; }
        @Override public jakarta.servlet.ServletContext getServletContext() { return null; }
        @Override public jakarta.servlet.AsyncContext startAsync() { return null; }
        @Override public jakarta.servlet.AsyncContext startAsync(jakarta.servlet.ServletRequest servletRequest, jakarta.servlet.ServletResponse servletResponse) { return null; }
        @Override public boolean isAsyncStarted() { return false; }
        @Override public boolean isAsyncSupported() { return false; }
        @Override public jakarta.servlet.AsyncContext getAsyncContext() { return null; }
        @Override public jakarta.servlet.DispatcherType getDispatcherType() { return jakarta.servlet.DispatcherType.REQUEST; }
        @Override public String getRequestId() { return ""; }
        @Override public String getProtocolRequestId() { return ""; }
        @Override public jakarta.servlet.ServletConnection getServletConnection() { return null; }
    }

    /** Status-recording no-op HttpServletResponse. */
    private static class FakeResponse implements HttpServletResponse {
        int status = 200;
        String contentType;
        final StringWriter body = new StringWriter();

        @Override public void setStatus(int sc) { this.status = sc; }
        @Override public void setContentType(String type) { this.contentType = type; }
        @Override public PrintWriter getWriter() { return new PrintWriter(body); }

        @Override public void addCookie(jakarta.servlet.http.Cookie cookie) {}
        @Override public boolean containsHeader(String name) { return false; }
        @Override public String encodeURL(String url) { return url; }
        @Override public String encodeRedirectURL(String url) { return url; }
        @Override public void sendError(int sc, String msg) {}
        @Override public void sendError(int sc) {}
        @Override public void sendRedirect(String location) {}
        @Override public void setDateHeader(String name, long date) {}
        @Override public void addDateHeader(String name, long date) {}
        @Override public void setHeader(String name, String value) {}
        @Override public void addHeader(String name, String value) {}
        @Override public void setIntHeader(String name, int value) {}
        @Override public void addIntHeader(String name, int value) {}
        @Override public int getStatus() { return status; }
        @Override public String getHeader(String name) { return null; }
        @Override public java.util.Collection<String> getHeaders(String name) { return List.of(); }
        @Override public java.util.Collection<String> getHeaderNames() { return List.of(); }
        @Override public String getCharacterEncoding() { return "UTF-8"; }
        @Override public String getContentType() { return contentType; }
        @Override public jakarta.servlet.ServletOutputStream getOutputStream() { return null; }
        @Override public void setCharacterEncoding(String charset) {}
        @Override public void setContentLength(int len) {}
        @Override public void setContentLengthLong(long len) {}
        @Override public void setBufferSize(int size) {}
        @Override public int getBufferSize() { return 0; }
        @Override public void flushBuffer() {}
        @Override public void resetBuffer() {}
        @Override public boolean isCommitted() { return false; }
        @Override public void reset() {}
        @Override public void setLocale(java.util.Locale loc) {}
        @Override public java.util.Locale getLocale() { return java.util.Locale.getDefault(); }
    }

    private AgentAdmitFilter buildFilter() {
        AgentAdmitConfig cfg = new AgentAdmitConfig();
        cfg.setApiKey("aa_test_dummy");
        return new AgentAdmitFilter(cfg, new AlwaysValidClient());
    }

    /** Runs the filter and returns the request so attributes can be inspected. */
    private FakeRequest runFilter(String authHeader) throws IOException, ServletException {
        AgentAdmitFilter filter = buildFilter();
        FakeRequest req = new FakeRequest(authHeader);
        FakeResponse resp = new FakeResponse();
        // FilterChain that does nothing — simulates passing through
        FilterChain chain = (rq, rs) -> {};
        filter.doFilter(req, resp, chain);
        return req;
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "Bearer ag_at_mytoken",
        "bearer ag_at_mytoken",
        "BEARER ag_at_mytoken",
        "BeArEr ag_at_mytoken"
    })
    void bearerSchemeCaseVariantsAreRecognized(String authHeader) throws Exception {
        FakeRequest req = runFilter(authHeader);
        assertEquals("agent", req.getAttribute("agentadmit.authType"),
            "Should recognize agent token for Authorization: " + authHeader);
    }

    @Test
    void tokenPrefixRemainsExactCaseSensitive() throws Exception {
        // AG_AT_ (upper) must NOT match the ag_at_ prefix
        FakeRequest req = runFilter("Bearer AG_AT_mytoken");
        assertNull(req.getAttribute("agentadmit.authType"),
            "Token prefix is case-sensitive; AG_AT_ must not match ag_at_");
    }

    @Test
    void noAuthHeaderPassesThrough() throws Exception {
        FakeRequest req = runFilter(null);
        assertNull(req.getAttribute("agentadmit.authType"),
            "No Authorization header: authType should be null");
    }

    @Test
    void nonAgentTokenPassesThrough() throws Exception {
        // Regular JWT -- the filter should let it through without setting agentadmit attributes
        FakeRequest req = runFilter("Bearer someregularjwttoken");
        assertNull(req.getAttribute("agentadmit.authType"),
            "Non-agent token should pass through without agentadmit attributes");
    }
}
