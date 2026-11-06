package com.agentadmit;

import java.util.Map;

/**
 * Agent designation: what the USER said on AgentAdmit's consent page about
 * which agent app a connection is for and, optionally, which AI model family
 * it mainly uses. It is the user's statement, recorded with the grant; it is
 * not a verified identity of the agent.
 *
 * <p>Review-time record only, never an enforcement input; authorization
 * decisions ride scopes, connection status, and consent.
 *
 * @param agentId the id of the app's list entry the user picked; {@code null}
 *                when the user typed a name that is not on the list
 * @param name    the agent app name the user chose (never empty)
 * @param source  always {@code "user_declared"}
 * @param model   the AI model family the user named; {@code null} when none
 */
public record DesignatedAgent(
    String agentId,
    String name,
    String source,
    Model model
) {

    /** The only source this SDK surfaces: the user's own statement. */
    public static final String SOURCE_USER_DECLARED = "user_declared";

    /**
     * The AI model family the user named on the consent page.
     *
     * @param modelId the id of the app's list entry the user picked;
     *                {@code null} when the user typed a name not on the list
     * @param name    the model family name the user chose (never empty)
     */
    public record Model(String modelId, String name) {}

    /**
     * Parse the {@code designated_agent} block out of a verify response (or
     * a webhook payload).
     *
     * <p>Strict: a non-empty string {@code name} and
     * {@code source: "user_declared"}, or the whole block is treated as
     * absent. A malformed {@code model} is dropped and the app is kept.
     * Values are never coerced, and a malformed block never fails a verify.
     *
     * @param raw the raw {@code designated_agent} value from the parsed response
     * @return the parsed designation, or {@code null} when absent or malformed
     */
    public static DesignatedAgent fromVerifyData(Object raw) {
        if (!(raw instanceof Map<?, ?> map)) {
            return null;
        }
        if (!(map.get("name") instanceof String name) || name.isEmpty()) {
            return null;
        }
        if (!SOURCE_USER_DECLARED.equals(map.get("source"))) {
            return null;
        }
        Model model = null;
        if (map.get("model") instanceof Map<?, ?> m
                && m.get("name") instanceof String modelName && !modelName.isEmpty()) {
            model = new Model(m.get("model_id") instanceof String id ? id : null, modelName);
        }
        String agentId = map.get("agent_id") instanceof String id ? id : null;
        return new DesignatedAgent(agentId, name, SOURCE_USER_DECLARED, model);
    }
}
