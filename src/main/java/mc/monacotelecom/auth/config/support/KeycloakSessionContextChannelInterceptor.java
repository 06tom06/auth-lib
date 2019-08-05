package mc.monacotelecom.auth.config.support;


import static mc.monacotelecom.auth.config.HttpSessionConfiguration.AUTHORIZATION_HEADER;
import static mc.monacotelecom.auth.config.HttpSessionConfiguration.AUTHORIZATION_HEADER_BEARER;
import static mc.monacotelecom.auth.config.HttpSessionConfiguration.SESSION_ATTR;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.keycloak.KeycloakPrincipal;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.springsecurity.KeycloakAuthenticationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.messaging.Message;
import org.springframework.messaging.MessageChannel;
import org.springframework.messaging.simp.SimpMessageHeaderAccessor;
import org.springframework.messaging.simp.stomp.StompCommand;
import org.springframework.messaging.simp.stomp.StompHeaderAccessor;
import org.springframework.messaging.support.ChannelInterceptor;
import org.springframework.messaging.support.MessageHeaderAccessor;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.session.MapSession;
import org.springframework.session.MapSessionRepository;
import org.springframework.stereotype.Component;

/**
 * Matches websocket session with the main http session
 * 
 * @param sessionRepository
 * @return
 */
@Component
public class KeycloakSessionContextChannelInterceptor implements ChannelInterceptor {
	
	@Autowired
	MapSessionRepository sessionRepository;

	@Autowired
	SessionRegistry sessionRegistry;
		
	@SuppressWarnings("unchecked")
	public Message<?> preSend(Message<?> message, MessageChannel channel) {
		StompHeaderAccessor accessor =
				MessageHeaderAccessor.getAccessor(message, StompHeaderAccessor.class);

		Map<String, Object> sessionHeaders = SimpMessageHeaderAccessor.getSessionAttributes(message.getHeaders());
		String sessionId = (String) sessionHeaders.get(SESSION_ATTR);
		Optional<MapSession> session = Optional.empty();
		if (sessionId != null) {
			session = Optional.ofNullable(sessionRepository.findById(sessionId));
			session.ifPresent(sessionRepository::save);
		} 
		
		if (!session.isPresent()) {
			throw new KeycloakAuthenticationException("Error comparing the Authorization token: The websocket requesting the channel "
					+ "is not associated to a session");
		}
		
	    if (StompCommand.CONNECT.equals(accessor.getCommand())) {
			List<String> authHeaders = accessor.getNativeHeader(AUTHORIZATION_HEADER);
			KeycloakPrincipal<KeycloakSecurityContext> kcp = (KeycloakPrincipal<KeycloakSecurityContext>) sessionRegistry.getSessionInformation(sessionId).getPrincipal();
			if (!authHeaders.contains(AUTHORIZATION_HEADER_BEARER + kcp.getKeycloakSecurityContext().getTokenString())) {
				throw new KeycloakAuthenticationException("Error comparing the Authorization token: The websocket requesting the channel "
						+ "is not associated to the principal session");
			}
        }

		return message;
	}
}
