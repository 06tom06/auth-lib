package mc.monacotelecom.auth.config;

import java.io.IOException;
import java.util.function.Consumer;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.keycloak.OAuth2Constants;
import org.keycloak.adapters.KeycloakConfigResolver;
import org.keycloak.adapters.springboot.KeycloakSpringBootConfigResolver;
import org.keycloak.adapters.springsecurity.KeycloakConfiguration;
import org.keycloak.adapters.springsecurity.authentication.KeycloakAuthenticationEntryPoint;
import org.keycloak.adapters.springsecurity.config.KeycloakWebSecurityConfigurerAdapter;
import org.keycloak.adapters.springsecurity.filter.KeycloakAuthenticationProcessingFilter;
import org.keycloak.adapters.springsecurity.filter.QueryParamPresenceRequestMatcher;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.actuate.autoconfigure.security.servlet.EndpointRequest;
import org.springframework.boot.actuate.health.HealthEndpoint;
import org.springframework.boot.actuate.info.InfoEndpoint;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestHeaderRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
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

	@Autowired
	KeycloakHttpSecurityCustomizer httpSecurityCustomizer;

	@Autowired
	KeycloakWebSecurityCustomizer webSecurityCustomizer;

	@Value("${sso.login-uri:/sso/login}")
	String loginUri;
	
	@Value("${sso.logout-uri:/sso/logout}")
	String logoutUri;

	private interface CheckedConsumer<T, E extends Throwable> {

		void accept(T t) throws E;

	}

	public interface KeycloakHttpSecurityCustomizer extends CheckedConsumer<HttpSecurity, Exception> { }

	public interface KeycloakWebSecurityCustomizer extends CheckedConsumer<WebSecurity, Exception> { }

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		httpSecurityCustomizer.accept(http);
	}

	@Override
	public void configure(WebSecurity web) throws Exception {
		webSecurityCustomizer.accept(web);
	}

	@Bean
    public RequestCache requestCache() {
		return new HttpSessionRequestCache();
	}

	@Bean
    @Override
    protected KeycloakAuthenticationProcessingFilter keycloakAuthenticationProcessingFilter() throws Exception {
        RequestMatcher requestMatcher =  new OrRequestMatcher(
                new AntPathRequestMatcher(loginUri),
                new RequestHeaderRequestMatcher(KeycloakAuthenticationProcessingFilter.AUTHORIZATION_HEADER),
                new QueryParamPresenceRequestMatcher(OAuth2Constants.ACCESS_TOKEN)
        );
        
        KeycloakAuthenticationProcessingFilter filter = new KeycloakAuthenticationProcessingFilter(authenticationManagerBean(), requestMatcher);
		filter.setSessionAuthenticationStrategy(sessionAuthenticationStrategy());
	
        return filter;
    }
    
    @Override
    protected AuthenticationEntryPoint authenticationEntryPoint() throws Exception {
        KeycloakAuthenticationEntryPoint keycloakAuthenticationEntryPoint = new KeycloakAuthenticationEntryPoint(adapterDeploymentContext()) {
        	protected void commenceLoginRedirect(HttpServletRequest request, HttpServletResponse response) throws IOException {
        		requestCache().saveRequest(request, response);
        		super.commenceLoginRedirect(request, response);
        	};
        };
        keycloakAuthenticationEntryPoint.setLoginUri(loginUri);
		return keycloakAuthenticationEntryPoint;
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

	@Bean
	@ConditionalOnMissingBean
	public KeycloakHttpSecurityCustomizer keycloakHttpSecurityCustomizer() {
		return http ->
			http.requestCache().requestCache(requestCache())
				.and()
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
					.logoutUrl(logoutUri).permitAll()
					.logoutSuccessUrl(loginUri)
				.and()
					.addFilterBefore(new SessionRepositoryFilter<>(sessionRepository), ChannelProcessingFilter.class)
					.cors().configurationSource(corsConfigurationSource)
				.and()
					.headers().frameOptions().sameOrigin()
				.and()
					.authorizeRequests()
					.requestMatchers(EndpointRequest.to(InfoEndpoint.class, HealthEndpoint.class)).permitAll()
					.requestMatchers(EndpointRequest.toAnyEndpoint()).hasRole("ACTUATOR")
					.anyRequest().authenticated();
	}

	@Bean
	@ConditionalOnMissingBean
	public KeycloakWebSecurityCustomizer keycloakWebSecurityCustomizer() {
		return web -> {};
	}
}