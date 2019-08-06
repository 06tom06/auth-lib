package mc.monacotelecom.auth.config;

import java.util.concurrent.ConcurrentHashMap;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.session.MapSession;
import org.springframework.session.MapSessionRepository;
import org.springframework.session.config.annotation.web.http.EnableSpringHttpSession;
import org.springframework.session.web.socket.server.SessionRepositoryMessageInterceptor;

@Configuration
@EnableSpringHttpSession
@ConditionalOnMissingBean(annotation=EnableSpringHttpSession.class)
public class HttpSessionConfiguration {
	public static final String AUTHORIZATION_HEADER = "Authorization";
	public static final String AUTHORIZATION_HEADER_BEARER = "Bearer ";

	@Bean
	public SessionRegistry sessionRegistry() {
		return new SessionRegistryImpl();
	}
	
	@Bean
	public MapSessionRepository sessionRepository() {
		return new MapSessionRepository(new ConcurrentHashMap<>());
	}
	
    @Bean
    public SessionRepositoryMessageInterceptor<MapSession> sessionRepositoryInterceptor() {
        return new SessionRepositoryMessageInterceptor<MapSession>(sessionRepository());
    }
}
