package mc.monacotelecom.auth.config.support;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.keycloak.KeycloakPrincipal;
import org.keycloak.adapters.AdapterDeploymentContext;
import org.keycloak.adapters.AdapterTokenStore;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.RefreshableKeycloakSecurityContext;
import org.keycloak.adapters.springsecurity.facade.SimpleHttpFacade;
import org.keycloak.adapters.springsecurity.token.SpringSecurityAdapterTokenStoreFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.integration.config.GlobalChannelInterceptor;
import org.springframework.messaging.Message;
import org.springframework.messaging.MessageChannel;
import org.springframework.messaging.support.ChannelInterceptor;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.stereotype.Component;
import org.springframework.util.SerializationUtils;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
@GlobalChannelInterceptor
@ConditionalOnBean(type = { "org.keycloak.adapters.AdapterDeploymentContext", "org.springframework.cloud.stream.binding.BindingService" })
@ConditionalOnClass(name= { "org.keycloak.adapters.AdapterDeploymentContext", "org.springframework.cloud.stream.binding.BindingService", "org.springframework.messaging.support.ChannelInterceptor" })
public class KeycloakSecurityContextPropagationInterceptor implements ChannelInterceptor {

	private static final String HEADER_SECURITY_AUTHENTICATION = "x-security-authentication";
	private static final String HEADER_PAYLOAD_CLASS = "x-class";
	
	@Autowired
	private HttpServletRequest request;
	
	@Autowired
	private HttpServletResponse response;
	
	@Autowired
	private AdapterDeploymentContext adapterDeploymentContext;

	@Override
	public Message<?> preSend(Message<?> message, MessageChannel mc) {
		SecurityContext securityContext = SecurityContextHolder.getContext();
		Authentication authentication = securityContext.getAuthentication();
		
		if (authentication == null) {
			log.debug("KeycloakSecurityContextPropagationInterceptor.preSend(): Attempt to restore SecurityContext");
			deserializeSecurityContext(message);
			return message;
		}
		log.debug("KeycloakSecurityContextPropagationInterceptor.preSend(): Attempt to propagate SecurityContext");
		return serializeSecurityContext(message, securityContext);
	}
	
	@Override
	public void afterReceiveCompletion(Message<?> message, MessageChannel channel, Exception ex) {
		log.debug("KeycloakSecurityContextPropagationInterceptor.afterReceiveCompletion(): Attempt to restore SecurityContext");
		deserializeSecurityContext(message); 
	}

	private Message<?> serializeSecurityContext(Message<?> message, SecurityContext securityContext) {
		Authentication authentication = securityContext.getAuthentication();
		if (authentication.getPrincipal() == null || !KeycloakPrincipal.class.isAssignableFrom(authentication.getPrincipal().getClass())) {
			log.debug("Cannot propagate Authentication: principal is not the expected KeycloakPrincipal type");
			return message;
		}
		Message<?> augmentedMessage = MessageBuilder.fromMessage(message)
				.setHeader(HEADER_PAYLOAD_CLASS, message.getPayload().getClass().getSimpleName())
				.setHeader(HEADER_SECURITY_AUTHENTICATION, SerializationUtils.serialize(authentication))
				.build();
		return augmentedMessage;
	}

	@SuppressWarnings("unchecked")
	private void deserializeSecurityContext(Message<?> message) {
		byte[] authentication = (byte[]) message.getHeaders().get(HEADER_SECURITY_AUTHENTICATION);
		if (authentication == null || authentication.length == 0) {
			log.debug("Cannot propagate Authentication: header x-security-context not set in the message");
			return;
		}
		if (SecurityContextHolder.getContext().getAuthentication() != null) {
			log.debug("Cannot propagate Authentication: an authentication is already present");
			return;
		}
		Authentication propagatedAuthentication = (Authentication) SerializationUtils.deserialize((byte[])authentication);
		if (!KeycloakPrincipal.class.isAssignableFrom(propagatedAuthentication.getPrincipal().getClass())) {
			log.debug("Cannot propagate Authentication: principal is not the expected KeycloakPrincipal type");
			return;
		}
		KeycloakPrincipal<RefreshableKeycloakSecurityContext> keycloakPrincipal = (KeycloakPrincipal<RefreshableKeycloakSecurityContext>) propagatedAuthentication.getPrincipal();
		RefreshableKeycloakSecurityContext keycloakSecurityContext = keycloakPrincipal.getKeycloakSecurityContext();
		if (!RefreshableKeycloakSecurityContext.class.isAssignableFrom(keycloakSecurityContext.getClass())) {
			log.debug("Cannot propagate Authentication: securityContext is not the expected RefreshableKeycloakSecurityContext type");
			return;
		}
		
		KeycloakDeployment deployment = adapterDeploymentContext.resolveDeployment(new SimpleHttpFacade(request, response));
		AdapterTokenStore tokenStore = new SpringSecurityAdapterTokenStoreFactory().createAdapterTokenStore(deployment, request);
		keycloakSecurityContext.setCurrentRequestInfo(deployment, tokenStore);
		keycloakSecurityContext.refreshExpiredToken(false);

		if (keycloakSecurityContext.isActive()) {
			SecurityContextHolder.setContext(new SecurityContextImpl(propagatedAuthentication));
		} else {
			log.error("Cannot propagate Authentication: RefreshableKeycloakSecurityContext is not active");
		}	
	}
}