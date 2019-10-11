package mc.monacotelecom.auth.config;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import mc.monacotelecom.auth.config.support.KeycloakScopePermissionEvaluator;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfiguration extends GlobalMethodSecurityConfiguration {

    @Override
    protected MethodSecurityExpressionHandler createExpressionHandler() {
        DefaultMethodSecurityExpressionHandler expressionHandler = 
          new DefaultMethodSecurityExpressionHandler();
        expressionHandler.setPermissionEvaluator(permissionEvaluator());
        return expressionHandler;
    }
    
    @Bean
    @ConditionalOnMissingBean
	public CorsConfigurationSource corsConfigurationSource() {
		return new UrlBasedCorsConfigurationSource();
	}
    
    /**
     * The keycloak permission evaluator useful for spring security ExpressionHandler configuration
     */
    @Bean
    @ConditionalOnMissingBean
    public PermissionEvaluator permissionEvaluator() {
    	return new KeycloakScopePermissionEvaluator();
    }


}
