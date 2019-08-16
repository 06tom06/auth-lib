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
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter;
import org.springframework.session.MapSessionRepository;
import org.springframework.session.web.http.SessionRepositoryFilter;
import org.springframework.web.cors.CorsConfigurationSource;


@KeycloakConfiguration
@ConditionalOnMissingBean(annotation=KeycloakConfiguration.class)
public class KeycloakSecurityConfiguration extends KeycloakWebSecurityConfigurerAdapter {

	@Autowired
	MapSessionRepository sessionRepository;

	@Autowired
	SessionRegistry sessionRegistry;

	@Autowired
	CorsConfigurationSource corsConfigurationSource;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
        	.csrf().requireCsrfProtectionMatcher(keycloakCsrfRequestMatcher())
        .and()
	        .sessionManagement()
	        .sessionAuthenticationStrategy(sessionAuthenticationStrategy())
        .and()
	        .addFilterBefore(keycloakPreAuthActionsFilter(), LogoutFilter.class)
	        .addFilterBefore(keycloakAuthenticationProcessingFilter(), BasicAuthenticationFilter.class)
	        .addFilterAfter(keycloakSecurityContextRequestFilter(), SecurityContextHolderAwareRequestFilter.class)
	        // This gives 403 .addFilterAfter(keycloakAuthenticatedActionsRequestFilter(), KeycloakSecurityContextRequestFilter.class)
	        .exceptionHandling().authenticationEntryPoint(authenticationEntryPoint())
        .and()
	        .logout()
	        .addLogoutHandler(keycloakLogoutHandler())
	        .logoutUrl("/sso/logout").permitAll()
		.and()
			.addFilterBefore(new SessionRepositoryFilter<>(sessionRepository), ChannelProcessingFilter.class)
			.cors().configurationSource(corsConfigurationSource)
		.and()
			.headers().frameOptions().sameOrigin()
		.and()
			.authorizeRequests()
			.anyRequest()
			.authenticated();
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

}