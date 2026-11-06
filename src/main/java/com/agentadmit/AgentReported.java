package com.agentadmit;

import java.util.Map;

/**
 * What the AGENT reported about itself when it redeemed the connection
 * token. Unverified: the hosted service records it as sent.
 *
 * <p>Review-time record only, never an enforcement input; authorization
 * decisions ride scopes, connection status, and consent.
 *
 * @param platform the platform the agent said it runs on; {@code null} when
 *                 it reported none
 * @param model    the model the agent said it uses; {@code null} when it
 *                 reported none
 */
public record AgentReported(
    String platform,
    Model model
) {

    /**
     * The model the agent said it uses.
     *
     * @param id      the model identifier the agent sent (never empty)
     * @param version the model version the agent sent; {@code null} when none
     */
    public record Model(String id, String version) {}

    /**
     * Parse the {@code agent_reported} block out of a verify response.
     *
     * <p>Present only when it carries a string platform or a model with a
     * string id. Values are never coerced, and a malformed block never fails
     * a verify.
     *
     * @param raw the raw {@code agent_reported} value from the parsed response
     * @return the parsed record, or {@code null} when it carries neither a
     *         platform nor a model id
     */
    public static AgentReported fromVerifyData(Object raw) {
        if (!(raw instanceof Map<?, ?> map)) {
            return null;
        }
        String platform = map.get("platform") instanceof String p && !p.isEmpty() ? p : null;
        Model model = null;
        if (map.get("model") instanceof Map<?, ?> m
                && m.get("id") instanceof String id && !id.isEmpty()) {
            model = new Model(id, m.get("version") instanceof String v ? v : null);
        }
        if (platform == null && model == null) {
            return null;
        }
        return new AgentReported(platform, model);
    }
}
