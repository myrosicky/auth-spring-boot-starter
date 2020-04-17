package org.ll.auth.config.auth.oauth2;

import java.util.stream.Collectors;

import org.ll.auth.model.Oauth2ClientDetailsProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.config.annotation.builders.InMemoryClientDetailsServiceBuilder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.client.InMemoryClientDetailsService;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

@Configuration
@ConditionalOnProperty("cloudms.security.auth.oauth2.enabled")
@Order(3)
public class OAuth2AuthorizationServerConfig extends WebSecurityConfigurerAdapter {

	private static final Logger LOG = LoggerFactory.getLogger(OAuth2AuthorizationServerConfig.class);
	private final static boolean isDebug = LOG.isDebugEnabled();
	
	
	@Configuration
	@EnableAuthorizationServer
	@ConditionalOnProperty("cloudms.security.auth.oauth2.enabled")
	public static class AuthorizationServer extends AuthorizationServerConfigurerAdapter {

		@Autowired private TokenStore tokenStore;
		
		@Autowired @Qualifier("authenticationManagerBean") private AuthenticationManager authenticationManager;
		
		@Autowired private JwtAccessTokenConverter tokenConverter;

		@Autowired private UserDetailsService userDetailsService;
		
		@Autowired private TokenEnhancer tokenEnhancer;
		
		@Bean
		@ConfigurationProperties("cloudms.security.auth.oauth2.client-details")
		public Oauth2ClientDetailsProperties oauth2ClientDetailsProperties(){
			return new Oauth2ClientDetailsProperties();
		}

		@Override
		public void configure(ClientDetailsServiceConfigurer clients) throws Exception {

			clients.setBuilder(new InMemoryClientDetailsServiceBuilder(){

				@Override
				protected ClientDetailsService performBuild() {
					InMemoryClientDetailsService clientDetailsService = new InMemoryClientDetailsService();
					
					if(isDebug){
						LOG.debug("oauth2ClientDetailsProperties().getClients():" + oauth2ClientDetailsProperties().getClients());
					}
					clientDetailsService.setClientDetailsStore(
							oauth2ClientDetailsProperties().getClients() 
							.stream()
							.collect(Collectors.toMap(ClientDetails::getClientId,  c -> c))
							);
					return clientDetailsService;
				}
				
			});
		}

		@Override
		public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
			endpoints
					.tokenStore(tokenStore)
					.accessTokenConverter(tokenConverter)
					
//					.tokenEnhancer(tokenEnhancer)
					
					.authenticationManager(authenticationManager)
					.userDetailsService(userDetailsService)
					;
		}

		@Override
		public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
			oauthServer.realm("sparklr2/client")
				.tokenKeyAccess("permitAll()")
				.checkTokenAccess("isAuthenticated()")
				.allowFormAuthenticationForClients()
			;
		}
		
	}
}
