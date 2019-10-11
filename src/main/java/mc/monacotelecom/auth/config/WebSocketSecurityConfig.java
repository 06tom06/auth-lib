package mc.monacotelecom.auth.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.simp.config.ChannelRegistration;
import org.springframework.messaging.simp.config.MessageBrokerRegistry;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.security.config.annotation.web.messaging.MessageSecurityMetadataSourceRegistry;
import org.springframework.security.config.annotation.web.socket.AbstractSecurityWebSocketMessageBrokerConfigurer;
import org.springframework.session.MapSession;
import org.springframework.session.MapSessionRepository;
import org.springframework.session.web.socket.server.SessionRepositoryMessageInterceptor;
import org.springframework.web.socket.config.annotation.EnableWebSocketMessageBroker;
import org.springframework.web.socket.config.annotation.StompEndpointRegistry;


@Configuration
@EnableScheduling
@EnableWebSocketMessageBroker
public class WebSocketSecurityConfig extends AbstractSecurityWebSocketMessageBrokerConfigurer {

	@Value("${cors.allowedOrigin:*}")
	String allowedOrigin;

	@Value("${messaging.broker.endpoint:/messages}")
	String messagingBrokerEndpoint;

	@Value("${messaging.broker.prefix:/app}")
	String messagingBrokerPrefix;

	@Value("${messaging.broker.topic:/topic}")
	String messagingBrokerTopic;

	@Autowired
	MapSessionRepository sessionRepository;

	@Override
	public void configureMessageBroker(MessageBrokerRegistry config) {
		config.enableSimpleBroker(messagingBrokerTopic);
		config.setApplicationDestinationPrefixes(messagingBrokerPrefix);
	}
	
	@Override
	protected void customizeClientInboundChannel(ChannelRegistration registration) {
		registration.interceptors(sessionRepositoryMessageInterceptor());
	}

	@Override
	protected void configureInbound(MessageSecurityMetadataSourceRegistry messages) {
		messages.anyMessage().anonymous();
	}

	@Override
	public void registerStompEndpoints(StompEndpointRegistry registry) {
		registry.addEndpoint(messagingBrokerEndpoint)
			.setAllowedOrigins(allowedOrigin)
			.withSockJS()
			.setInterceptors(sessionRepositoryMessageInterceptor());
	}
	
	@Override
	protected boolean sameOriginDisabled() {
		return true;
	}

	@Bean
	public SessionRepositoryMessageInterceptor<MapSession> sessionRepositoryMessageInterceptor() {
		return new SessionRepositoryMessageInterceptor<MapSession>(sessionRepository);
	}
}