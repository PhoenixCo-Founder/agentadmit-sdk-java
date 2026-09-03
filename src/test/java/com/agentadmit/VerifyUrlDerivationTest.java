package com.agentadmit;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Regression from the TrainerTracer dogfood rig (Sep 3, 2026): an operator who
 * points {@code agentadmit.api-url} at a staging service or a local rig and
 * leaves {@code agentadmit.verify-url} alone expects verify to follow.
 * Otherwise every per-call verify silently goes to production while everything
 * else talks to the configured service. An explicitly configured verify URL
 * always wins.
 */
class VerifyUrlDerivationTest {

    @Test
    void defaultsAreUnchanged() {
        assertEquals("https://api.agentadmit.com/api/v1/verify", new AgentAdmitConfig().getVerifyUrl());
    }

    @Test
    void verifyUrlFollowsANonDefaultApiUrl() {
        AgentAdmitConfig local = new AgentAdmitConfig();
        local.setApiUrl("http://127.0.0.1:3003");
        assertEquals("http://127.0.0.1:3003/api/v1/verify", local.getVerifyUrl());

        AgentAdmitConfig staging = new AgentAdmitConfig();
        staging.setApiUrl("https://staging.agentadmit.example/");
        assertEquals("https://staging.agentadmit.example/api/v1/verify", staging.getVerifyUrl(),
            "a trailing slash does not double up");
    }

    @Test
    void anExplicitVerifyUrlAlwaysWins() {
        AgentAdmitConfig config = new AgentAdmitConfig();
        config.setApiUrl("http://localhost:9000");
        config.setVerifyUrl("http://localhost:9000/verify");
        assertEquals("http://localhost:9000/verify", config.getVerifyUrl());

        AgentAdmitConfig reverseOrder = new AgentAdmitConfig();
        reverseOrder.setVerifyUrl("http://localhost:9000/verify");
        reverseOrder.setApiUrl("http://localhost:9000");
        assertEquals("http://localhost:9000/verify", reverseOrder.getVerifyUrl(),
            "property binding order must not change the outcome");
    }

    @Test
    void aDefaultApiUrlNeverDerives() {
        AgentAdmitConfig config = new AgentAdmitConfig();
        config.setApiUrl("https://api.agentadmit.com/");
        assertEquals("https://api.agentadmit.com/api/v1/verify", config.getVerifyUrl());
    }
}
