package mc.monacotelecom.auth.config;

import java.util.Map;

import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.messaging.simp.config.ChannelRegistration;
import org.springframework.messaging.simp.config.MessageBrokerRegistry;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.session.Session;
import org.springframework.session.web.socket.config.annotation.AbstractSessionWebSocketMessageBrokerConfigurer;
import org.springframework.web.socket.WebSocketHandler;
import org.springframework.web.socket.config.annotation.EnableWebSocketMessageBroker;
import org.springframework.web.socket.config.annotation.StompEndpointRegistry;
import org.springframework.web.socket.server.HandshakeInterceptor;

import mc.monacotelecom.auth.config.support.KeycloakSessionContextChannelInterceptor;


@Configuration
@EnableScheduling
@EnableWebSocketMessageBroker
public class WebSocketConfig extends AbstractSessionWebSocketMessageBrokerConfigurer<Session> {

	@Autowired
	KeycloakSessionContextChannelInterceptor keycloakSessionContextChannelInterceptor;
	
	@Value("${cors.allowed_origin:*}")
	String allowedOrigin;
	
	@Value("${messaging.broker.endpoint:/messages}")
	String messagingBrokerEndpoint;
	
	@Value("${messaging.broker.prefix:/app}")
	String messagingBrokerPrefix;
	
	@Value("${messaging.broker.topic:/topic}")
	String messagingBrokerTopic;

	@Override
	public void configureClientInboundChannel(ChannelRegistration registration) {
		registration.interceptors(keycloakSessionContextChannelInterceptor);
	}

	@Override
	public void configureMessageBroker(MessageBrokerRegistry registry) {
		registry.setApplicationDestinationPrefixes(messagingBrokerPrefix)//
				.enableSimpleBroker(messagingBrokerTopic);
	}

	@Override
	protected void configureStompEndpoints(StompEndpointRegistry registry) {
		registry.addEndpoint(messagingBrokerEndpoint)//
				.setAllowedOrigins(allowedOrigin)
				.withSockJS()//
				.setInterceptors(new HttpSessionIdHandshakeInterceptor());
	}

}

class HttpSessionIdHandshakeInterceptor implements HandshakeInterceptor {

	@Override
	public void afterHandshake(ServerHttpRequest request, ServerHttpResponse response, WebSocketHandler wsHandler, Exception ex) {
	}

	@Override
	public boolean beforeHandshake(ServerHttpRequest request, ServerHttpResponse response, WebSocketHandler wsHandler, Map<String, Object> attributes) throws Exception {
		if (request instanceof ServletServerHttpRequest) {
			ServletServerHttpRequest servletRequest = (ServletServerHttpRequest) request;
			HttpSession session = servletRequest.getServletRequest().getSession(false);
			if (session != null) {
				attributes.put(HttpSessionConfiguration.SESSION_ATTR, session.getId());
			}
		}
		return true;
	}
}