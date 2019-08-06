package mc.monacotelecom.auth.config.support;

import java.io.Serializable;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;

import org.keycloak.KeycloakPrincipal;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.authorization.client.ClientAuthorizationContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

public class KeycloakScopePermissionEvaluator implements PermissionEvaluator {

	private static final Logger logger = LoggerFactory.getLogger(KeycloakScopePermissionEvaluator.class);
	
    @Override
    public boolean hasPermission(
      Authentication auth, Object targetDomainObject, Object permission) {
        if ((auth == null) || (targetDomainObject == null) || !(permission instanceof String)){
            return false;
        }
        return hasScope(auth, targetDomainObject.toString(), permission.toString());
    }
 
    @Override
    public boolean hasPermission(Authentication auth, Serializable targetId, String targetType, Object permission) {
        throw new UnsupportedOperationException("Please use the signature hasPermission([resourceName], [scopeName])");
    }
    
    @SuppressWarnings("unchecked")
	private boolean hasScope(Authentication auth, String resourceName, String scopeName) {
    	if (KeycloakPrincipal.class.isAssignableFrom(auth.getPrincipal().getClass())) {
    		KeycloakPrincipal<KeycloakSecurityContext> kcp = (KeycloakPrincipal<KeycloakSecurityContext>) auth.getPrincipal();
        	ClientAuthorizationContext authorizationContext = (ClientAuthorizationContext) kcp.getKeycloakSecurityContext().getAuthorizationContext();
        	return evaluate(resourceName, scopeName, authorizationContext);
    	}
    	logger.error("Cannot evaluate permission of principal " + auth.getPrincipal());
    	return false;
    }
    
    private static String getCurrentUri() {
        RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
        if (requestAttributes instanceof ServletRequestAttributes) {
            HttpServletRequest request = ((ServletRequestAttributes)requestAttributes).getRequest();
            return request.getRequestURI();
        }
        logger.debug("Not called in the context of an HTTP request");
        return "(unknown)";
    }

	private boolean evaluate(String resourceName, String scopeName, ClientAuthorizationContext authorizationContext) {
		boolean hasPermission;
		if (resourceName.isEmpty()) {
			hasPermission = authorizationContext.hasScopePermission(scopeName);
    	} else {
    		hasPermission = authorizationContext.hasPermission(resourceName, scopeName);
    	}
		if (!hasPermission) {
			String available = authorizationContext.getPermissions().stream()
				.map(p -> p.getResourceName() + "=" + p.getScopes()
					.stream().collect(Collectors.joining(", ", "{", "}"))
				).collect(Collectors.joining(", ", "[", "]"));
			logger.error("Refused permission for resource [" + resourceName + "={" + scopeName + "}]: authorization.isGranted() = " + authorizationContext.isGranted() + " and available permissions are " + available + " for url " + getCurrentUri());
		}
		return hasPermission;
	}
}