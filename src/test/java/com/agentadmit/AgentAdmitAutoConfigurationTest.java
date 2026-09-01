package com.agentadmit;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies that AgentAdmitAutoConfiguration registers the required beans
 * when no consumer-provided beans are present, and does not double-register
 * when consumer beans are already in the context.
 */
class AgentAdmitAutoConfigurationTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(AgentAdmitAutoConfiguration.class));

    @Test
    void autoConfigurationRegistersFilterAspectAndSupportingBeans() {
        contextRunner.run(ctx -> {
            assertThat(ctx).hasSingleBean(AgentAdmitConfig.class);
            assertThat(ctx).hasSingleBean(IntrospectionClient.class);
            assertThat(ctx).hasSingleBean(AgentAdmitFilter.class);
            assertThat(ctx).hasSingleBean(RequiredScopeResolver.class);
            assertThat(ctx).hasSingleBean(ScopeEnforcementAspect.class);
            assertThat(ctx).hasSingleBean(AlertsClient.class);
            assertThat(ctx).hasSingleBean(TokensClient.class);
        });
    }

    @Test
    void userProvidedFilterBeanIsNotOverridden() {
        AgentAdmitConfig cfg = new AgentAdmitConfig();
        cfg.setApiKey("aa_test_custom");
        IntrospectionClient client = new IntrospectionClient(cfg);
        AgentAdmitFilter userFilter = new AgentAdmitFilter(cfg, client);

        contextRunner
                .withBean(AgentAdmitFilter.class, () -> userFilter)
                .run(ctx -> {
                    // Only one filter -- the user-provided one.
                    assertThat(ctx).hasSingleBean(AgentAdmitFilter.class);
                    assertThat(ctx.getBean(AgentAdmitFilter.class)).isSameAs(userFilter);
                });
    }
}
