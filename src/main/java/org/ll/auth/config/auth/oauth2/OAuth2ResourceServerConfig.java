package org.ll.auth.config.auth.oauth2;

import org.ll.auth.model.AuthorizeReqProperties;
import org.ll.auth.util.AntMatcherUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;

@Configuration
@ConditionalOnProperty("cloudms.security.resource.enabled")
@EnableWebSecurity
//@EnableWebFluxSecurity
@Order(4)
public class OAuth2ResourceServerConfig extends WebSecurityConfigurerAdapter {

	private static final Logger LOG = LoggerFactory.getLogger(OAuth2ResourceServerConfig.class);
	private boolean isDebug = LOG.isDebugEnabled();

	@Value("${cloudms.security.resource.resource-id}") private String resourceIdGateway;
	
	@Bean
	@ConfigurationProperties("cloudms.security.resource.authorize-request")
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
			AuthorizeReqProperties authorizeReqProperties = authorizeReqProperties();
			// @formatter:off
			http
				// Since we want the protected resources to be accessible in the UI as well we need 
				// session creation to be allowed (it's disabled by default in 2.0.6)
				.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
			.and()
//				.requestMatchers().antMatchers("/v1/**", "/apis/**", "/oauth/users/**", "/oauth/clients/**","/me")
				.requestMatchers().antMatchers(AntMatcherUtil.resolvePatterns(authorizeReqProperties))
			
//			.and()
//				.authorizeRequests()
//					.antMatchers("/v1/**", "/apis/**").access("#oauth2.clientHasAnyRole('ROLE_CLIENT', 'ROLE_QUERY', 'ROLE_USER') or hasAnyRole('ROLE_ADMIN', 'ROLE_API_USER', 'ROLE_USER', 'ROLE_QUERY')  ")
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
			
			AntMatcherUtil.setAuthorizeRequests(http.authorizeRequests(), authorizeReqProperties);
			// @formatter:on
		}
	}
	
}
