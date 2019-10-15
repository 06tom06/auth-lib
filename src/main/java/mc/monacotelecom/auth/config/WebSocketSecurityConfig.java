package mc.monacotelecom.auth.config;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
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
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.socket.config.annotation.EnableWebSocketMessageBroker;
import org.springframework.web.socket.config.annotation.StompEndpointRegistry;


@Configuration
@EnableScheduling
@EnableWebSocketMessageBroker
@ConditionalOnClass(AbstractSecurityWebSocketMessageBrokerConfigurer.class)
@ConditionalOnWebApplication
public class WebSocketSecurityConfig extends AbstractSecurityWebSocketMessageBrokerConfigurer {

	@Value("${messaging.broker.endpoint:/messages}")
	String messagingBrokerEndpoint;

	@Value("${messaging.broker.prefix:/app}")
	String messagingBrokerPrefix;

	@Value("${messaging.broker.topic:/topic}")
	String messagingBrokerTopic;

	@Autowired
	MapSessionRepository sessionRepository;

	@Autowired
	CorsConfigurationSource corsConfigurationSource;
	
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
		List<String> corsAllowedOrigins = new ArrayList<>();
		if (UrlBasedCorsConfigurationSource.class.isAssignableFrom(corsConfigurationSource.getClass())) {
			Map<String, CorsConfiguration> corsConfigurations = ((UrlBasedCorsConfigurationSource) corsConfigurationSource).getCorsConfigurations();
			corsConfigurations.forEach((path, conf) -> conf.getAllowedOrigins().stream().forEach(corsAllowedOrigins::add));
		}
		registry.addEndpoint(messagingBrokerEndpoint)
			.setAllowedOrigins(corsAllowedOrigins.toArray(new String[0]))
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