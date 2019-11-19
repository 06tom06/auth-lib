package mc.monacotelecom.auth.config;

import org.keycloak.adapters.KeycloakConfigResolver;
import org.keycloak.adapters.springboot.KeycloakSpringBootConfigResolver;
import org.keycloak.adapters.springsecurity.KeycloakConfiguration;
import org.keycloak.adapters.springsecurity.config.KeycloakWebSecurityConfigurerAdapter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.preauth.x509.X509AuthenticationFilter;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.web.cors.CorsConfigurationSource;

import javax.servlet.http.HttpServletResponse;
@Order(99)
@KeycloakConfiguration
@ConditionalOnMissingBean(annotation=KeycloakConfiguration.class)
@ConditionalOnMissingClass("org.springframework.security.config.annotation.web.socket.AbstractSecurityWebSocketMessageBrokerConfigurer")
@ConditionalOnWebApplication
public class KeycloakSecurityStatelessConfiguration extends KeycloakWebSecurityConfigurerAdapter {

	@Autowired
	CorsConfigurationSource corsConfigurationSource;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		super.configure(http);
		http.csrf().disable()
				.sessionManagement()
				.sessionAuthenticationStrategy(sessionAuthenticationStrategy())
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
				.and()
				.addFilterBefore(keycloakPreAuthActionsFilter(), LogoutFilter.class)
				.addFilterBefore(keycloakAuthenticationProcessingFilter(), X509AuthenticationFilter.class)
				.exceptionHandling().accessDeniedHandler((request, response, exception) -> response.setStatus(HttpServletResponse.SC_UNAUTHORIZED))
				.and()
				.logout()
				.addLogoutHandler(keycloakLogoutHandler())
				.logoutUrl("/logout").logoutSuccessHandler((request, response, authentication) -> response.setStatus(HttpServletResponse.SC_OK))
				.and()
				.cors().configurationSource(corsConfigurationSource)
				.and()
				.antMatcher("/actuator/health").antMatcher("/actuator/info").anonymous()
				.and()
				.authorizeRequests().anyRequest().authenticated();
	}

	@Override
	public void configure(WebSecurity web) throws Exception {
		super.configure(web);
		web.ignoring().antMatchers("/actuator/health", "/actuator/info");
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
		return new NullAuthenticatedSessionStrategy();
	}

	/**
	 * Resolves keycloak config in application.yml
	 */
	@Bean
	public KeycloakConfigResolver keycloakConfigResolver() {
		return new KeycloakSpringBootConfigResolver();
	}
}