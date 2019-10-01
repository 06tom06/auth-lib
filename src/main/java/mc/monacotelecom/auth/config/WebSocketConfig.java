package mc.monacotelecom.auth.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.simp.config.ChannelRegistration;
import org.springframework.messaging.simp.config.MessageBrokerRegistry;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.session.MapSession;
import org.springframework.session.MapSessionRepository;
import org.springframework.session.Session;
import org.springframework.session.web.socket.config.annotation.AbstractSessionWebSocketMessageBrokerConfigurer;
import org.springframework.session.web.socket.server.SessionRepositoryMessageInterceptor;
import org.springframework.web.socket.config.annotation.EnableWebSocketMessageBroker;
import org.springframework.web.socket.config.annotation.StompEndpointRegistry;


@Configuration
@EnableScheduling
@EnableWebSocketMessageBroker
public class WebSocketConfig extends AbstractSessionWebSocketMessageBrokerConfigurer<Session> {
	
	@Value("${cors.allowed_origin:*}")
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
	public void configureClientInboundChannel(ChannelRegistration registration) {
		registration.interceptors(sessionRepositoryMessageInterceptor());
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
				.setInterceptors(sessionRepositoryMessageInterceptor());
	}
	
    @Bean
    public SessionRepositoryMessageInterceptor<MapSession> sessionRepositoryMessageInterceptor() {
        return new SessionRepositoryMessageInterceptor<MapSession>(sessionRepository);
    }

}