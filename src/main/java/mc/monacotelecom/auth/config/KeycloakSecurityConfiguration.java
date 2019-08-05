package mc.monacotelecom.auth.config;

import org.keycloak.adapters.KeycloakConfigResolver;
import org.keycloak.adapters.springboot.KeycloakSpringBootConfigResolver;
import org.keycloak.adapters.springsecurity.KeycloakConfiguration;
import org.keycloak.adapters.springsecurity.config.KeycloakWebSecurityConfigurerAdapter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.session.MapSessionRepository;
import org.springframework.session.web.http.SessionRepositoryFilter;
import org.springframework.web.cors.CorsConfigurationSource;

import mc.monacotelecom.auth.config.support.KeycloakScopePermissionEvaluator;


@KeycloakConfiguration
@ConditionalOnMissingBean(annotation=KeycloakConfiguration.class)
public class KeycloakSecurityConfiguration extends KeycloakWebSecurityConfigurerAdapter {

	@Autowired
	MapSessionRepository sessionRepository;
	
	@Autowired
	SessionRegistry sessionRegistry;
	
	@Autowired(required=false)
	CorsConfigurationSource corsConfigurationSource;
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		 http
		 	.authenticationProvider(keycloakAuthenticationProvider())
		 	.addFilterBefore(new SessionRepositoryFilter<>(sessionRepository), ChannelProcessingFilter.class)
		 	.cors().configurationSource(corsConfigurationSource)
	 	.and()
		 	.csrf().disable()
		 	.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
	 	.and()
	 		.headers().frameOptions().sameOrigin()
		.and()
			.authorizeRequests()
			.anyRequest()
			.permitAll();
	}
	
    /**
     * Registers the KeycloakAuthenticationProvider with the authentication manager.
     */
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(keycloakAuthenticationProvider());
    }
	
    /**
     * Defines the session authentication strategy.
     */
    @Bean
    @Override
    protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
        return new RegisterSessionAuthenticationStrategy(sessionRegistry);
    }

    /**
     * Resolves keycloak config in application.yml
     */
    @Bean
    public KeycloakConfigResolver keycloakConfigResolver() {
        return new KeycloakSpringBootConfigResolver();
    }
    
    /**
     * The keycloak permission evaluator useful for spring security ExpressionHandler configuration
     */
    @Bean
    public KeycloakScopePermissionEvaluator permissionEvaluator() {
    	return new KeycloakScopePermissionEvaluator();
    }
}