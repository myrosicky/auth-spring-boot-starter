package org.ll.auth_spring_boot_starter.config;

import java.util.List;
import java.util.stream.Collectors;

import org.ll.auth_spring_boot_starter.model.AuthorizeReqProperties;
import org.ll.auth_spring_boot_starter.model.MatcherProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.AbstractRequestMatcherRegistry;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer.AuthorizedUrl;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer.ExpressionInterceptUrlRegistry;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;

@Configuration
@ConditionalOnProperty("security.resource.enabled")
@EnableWebSecurity
@Order(4)
public class OAuth2ResourceServerConfig extends WebSecurityConfigurerAdapter {

	private static final Logger LOG = LoggerFactory.getLogger(OAuth2ResourceServerConfig.class);
	private boolean isDebug = LOG.isDebugEnabled();
	
	@Value("${security.resource.resource-id}") private String resourceIdGateway;
	
	@Bean
	@ConfigurationProperties("security.resource.authorize-request")
	public AuthorizeReqProperties authorizeReqProperties(){
		return new AuthorizeReqProperties();
	}
	
//	@Value("${constant.gateway-path.log}") private String logPath;
	
	@Configuration
	@EnableResourceServer
	public class ResourceServer extends ResourceServerConfigurerAdapter {

		@Autowired private ResourceServerTokenServices tokenServices;
		
		@Override
		public void configure(ResourceServerSecurityConfigurer resources) {
			resources.resourceId(resourceIdGateway).tokenServices(tokenServices).stateless(false);
		}

		@Override
		public void configure(HttpSecurity http) throws Exception {
			List<MatcherProperties> matchers = authorizeReqProperties().getMatchers();
			// @formatter:off
			http
				// Since we want the protected resources to be accessible in the UI as well we need 
				// session creation to be allowed (it's disabled by default in 2.0.6)
				.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
			.and()
//				.requestMatchers().antMatchers("/v1/api/**", "/apis/**", "/oauth/users/**", "/oauth/clients/**","/me")
				.requestMatchers().antMatchers(matchers.stream().map(MatcherProperties::getPattern).collect(Collectors.toList()).toArray(new String[matchers.size()]))
			
//			.and()
//				.authorizeRequests()
//					.antMatchers("/v1/api/**, /apis/**").access("#oauth2.clientHasAnyRole('ROLE_CLIENT', 'ROLE_QUERY', 'ROLE_USER') or hasAnyRole('ROLE_ADMIN', 'ROLE_API_USER', 'ROLE_USER', 'ROLE_QUERY')  ")
//					.antMatchers("/me").access("#oauth2.hasScope('read')")					
//					.antMatchers("/photos").access("#oauth2.hasScope('read') or (!#oauth2.isOAuth() and hasRole('ROLE_USER'))")                                        
//					.antMatchers("/photos/trusted/**").access("#oauth2.hasScope('trust')")
//					.antMatchers("/photos/user/**").access("#oauth2.hasScope('trust')")					
//					.antMatchers("/photos/**").access("#oauth2.hasScope('read') or (!#oauth2.isOAuth() and hasRole('ROLE_USER'))")
//					.regexMatchers(HttpMethod.DELETE, "/oauth/users/([^/].*?)/tokens/.*")
//						.access("#oauth2.clientHasRole('ROLE_CLIENT') and (hasRole('ROLE_USER') or #oauth2.isClient()) and #oauth2.hasScope('write')")
//					.regexMatchers(HttpMethod.GET, "/oauth/clients/([^/].*?)/users/.*")
//						.access("#oauth2.clientHasRole('ROLE_CLIENT') and (hasRole('ROLE_USER') or #oauth2.isClient()) and #oauth2.hasScope('read')")
//					.regexMatchers(HttpMethod.GET, "/oauth/clients/.*")
//						.access("#oauth2.clientHasRole('ROLE_CLIENT') and #oauth2.isClient() and #oauth2.hasScope('read')")
				;
			if(isDebug){
				LOG.debug("matchers:" + matchers);
			}
			AbstractRequestMatcherRegistry<ExpressionUrlAuthorizationConfigurer<HttpSecurity>.AuthorizedUrl> registry = http.authorizeRequests();
			matchers.stream()
				.forEach(m -> registry.antMatchers(m.getPattern()).access(m.getAttribute()))
				; 
			// @formatter:on
		}
	}
	
}
