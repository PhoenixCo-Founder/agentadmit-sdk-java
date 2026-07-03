package com.agentadmit;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for M3 HTTPS enforcement on AgentAdmitConfig URL setters.
 *
 * Non-HTTPS URLs must throw an IllegalArgumentException at configuration time,
 * except for plain HTTP on loopback addresses (localhost, 127.0.0.1, [::1]).
 */
class HttpsEnforcementTest {

    // -------------------------------------------------------------------------
    // verifyUrl
    // -------------------------------------------------------------------------

    @Test
    void httpsVerifyUrlIsAccepted() {
        AgentAdmitConfig config = new AgentAdmitConfig();
        assertDoesNotThrow(() -> config.setVerifyUrl("https://api.agentadmit.com/api/v1/verify"));
        assertEquals("https://api.agentadmit.com/api/v1/verify", config.getVerifyUrl());
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "http://localhost:8080/verify",
        "http://localhost/verify",
        "http://127.0.0.1/verify",
        "http://127.0.0.1:9000/verify",
        "http://[::1]/verify",
        "http://[::1]:8080/verify"
    })
    void httpLoopbackVerifyUrlIsAccepted(String url) {
        AgentAdmitConfig config = new AgentAdmitConfig();
        assertDoesNotThrow(() -> config.setVerifyUrl(url), "Should accept loopback URL: " + url);
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "http://example.com/verify",
        "http://api.agentadmit.com/verify",
        "http://10.0.0.1/verify",
        "http://192.168.1.1/verify",
        "ftp://api.agentadmit.com/verify"
    })
    void nonHttpsNonLoopbackVerifyUrlIsRejected(String url) {
        AgentAdmitConfig config = new AgentAdmitConfig();
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
            () -> config.setVerifyUrl(url), "Should reject: " + url);
        assertTrue(ex.getMessage().contains("HTTPS"), "Error should mention HTTPS: " + ex.getMessage());
        assertTrue(ex.getMessage().contains("verifyUrl"), "Error should identify the field: " + ex.getMessage());
    }

    // -------------------------------------------------------------------------
    // apiUrl
    // -------------------------------------------------------------------------

    @Test
    void httpsApiUrlIsAccepted() {
        AgentAdmitConfig config = new AgentAdmitConfig();
        assertDoesNotThrow(() -> config.setApiUrl("https://api.agentadmit.com"));
        assertEquals("https://api.agentadmit.com", config.getApiUrl());
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "http://localhost:8080",
        "http://127.0.0.1",
        "http://[::1]:9000"
    })
    void httpLoopbackApiUrlIsAccepted(String url) {
        AgentAdmitConfig config = new AgentAdmitConfig();
        assertDoesNotThrow(() -> config.setApiUrl(url), "Should accept loopback URL: " + url);
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "http://example.com",
        "http://api.agentadmit.com",
        "ftp://api.agentadmit.com"
    })
    void nonHttpsNonLoopbackApiUrlIsRejected(String url) {
        AgentAdmitConfig config = new AgentAdmitConfig();
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
            () -> config.setApiUrl(url), "Should reject: " + url);
        assertTrue(ex.getMessage().contains("HTTPS"), "Error should mention HTTPS: " + ex.getMessage());
        assertTrue(ex.getMessage().contains("apiUrl"), "Error should identify the field: " + ex.getMessage());
    }

    @Test
    void blankUrlIsNotRejected() {
        // Blank/null values pass through -- other validators handle required fields.
        AgentAdmitConfig config = new AgentAdmitConfig();
        assertDoesNotThrow(() -> config.setVerifyUrl(""));
        assertDoesNotThrow(() -> config.setApiUrl(""));
    }
}
