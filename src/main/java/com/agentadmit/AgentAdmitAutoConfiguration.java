package com.agentadmit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

/**
 * Spring Boot auto-configuration for AgentAdmit SDK.
 *
 * <p>Registers the filter, AOP aspect, and supporting beans so that scope
 * enforcement is active without requiring consumers to component-scan
 * {@code com.agentadmit}. Each bean is guarded by
 * {@link ConditionalOnMissingBean} so that a consumer-provided definition
 * takes precedence (no double-registration when the consumer also
 * component-scans the package).
 *
 * <p>Logs one INFO line on startup to confirm that enforcement is active.
 */
@AutoConfiguration
@EnableConfigurationProperties(AgentAdmitConfig.class)
@EnableAspectJAutoProxy
public class AgentAdmitAutoConfiguration {

    private static final Logger logger = LoggerFactory.getLogger(AgentAdmitAutoConfiguration.class);

    /**
     * Register {@link IntrospectionClient} as a bean if not already present.
     *
     * @param config AgentAdmit configuration
     * @return the introspection client bean
     */
    @Bean
    @ConditionalOnMissingBean
    public IntrospectionClient agentAdmitIntrospectionClient(AgentAdmitConfig config) {
        return new IntrospectionClient(config);
    }

    /**
     * Register the default {@link RequiredScopeResolver} if not already
     * present: a {@link HandlerMappingScopeResolver} that reads
     * {@link RequireScope} / {@link RequireScopeIfAgent} off the Spring MVC
     * handler method mapped to the request, so the filter can declare
     * {@code scope_used} on the verify call. In a context without a
     * {@link RequestMappingHandlerMapping} the resolver resolves {@code null}
     * for every request and the field is simply omitted.
     *
     * @param handlerMappings lazily provides the MVC handler mapping when the
     *                        context has one
     * @return the required-scope resolver bean
     */
    @Bean
    @ConditionalOnMissingBean
    public RequiredScopeResolver agentAdmitRequiredScopeResolver(
            ObjectProvider<RequestMappingHandlerMapping> handlerMappings) {
        return new HandlerMappingScopeResolver(handlerMappings::getIfAvailable);
    }

    /**
     * Register {@link AgentAdmitFilter} as a bean if not already present.
     * Logs a confirmation that scope enforcement is active.
     *
     * @param config              AgentAdmit configuration
     * @param introspectionClient the introspection client
     * @param requiredScopeResolver resolver used to declare {@code scope_used}
     *                              audit telemetry on verify calls
     * @return the filter bean
     */
    @Bean
    @ConditionalOnMissingBean
    public AgentAdmitFilter agentAdmitFilter(AgentAdmitConfig config,
                                              IntrospectionClient introspectionClient,
                                              RequiredScopeResolver requiredScopeResolver) {
        logger.info("AgentAdmit scope enforcement is active (filter + aspect registered).");
        return new AgentAdmitFilter(config, introspectionClient, requiredScopeResolver);
    }

    /**
     * Register {@link ScopeEnforcementAspect} as a bean if not already present.
     *
     * @return the scope enforcement aspect bean
     */
    @Bean
    @ConditionalOnMissingBean
    public ScopeEnforcementAspect agentAdmitScopeEnforcementAspect() {
        return new ScopeEnforcementAspect();
    }

    /**
     * Register {@link AlertsClient} as a bean if not already present.
     *
     * @param config AgentAdmit configuration
     * @return the alerts client bean
     */
    @Bean
    @ConditionalOnMissingBean
    public AlertsClient agentAdmitAlertsClient(AgentAdmitConfig config) {
        return new AlertsClient(config);
    }

    /**
     * Register {@link TokensClient} as a bean if not already present.
     *
     * @param config AgentAdmit configuration
     * @return the tokens client bean
     */
    @Bean
    @ConditionalOnMissingBean
    public TokensClient agentAdmitTokensClient(AgentAdmitConfig config) {
        return new TokensClient(config);
    }
}
