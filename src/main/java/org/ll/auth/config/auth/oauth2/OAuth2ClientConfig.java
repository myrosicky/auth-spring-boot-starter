package org.ll.auth.config.auth.oauth2;

import javax.servlet.Filter;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpSession;

import org.ll.auth.config.auth.AuthConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.resource.BaseOAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServerOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.WebClient;



@Configuration
@ConditionalOnProperty("cloudms.security.client.oauth2.enabled")
@ConditionalOnMissingBean({AuthConfig.class, OAuth2AuthorizationServerConfig.class})
@EnableWebSecurity
@EnableOAuth2Client
@Order(2)
public class OAuth2ClientConfig extends WebSecurityConfigurerAdapter {

	private static final Logger LOG = LoggerFactory.getLogger(OAuth2ClientConfig.class);
	private boolean isDebug = LOG.isDebugEnabled();
	
	@Value("${cloudms.security.login.success-url}") private String successUrl;
	

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http
        		.requestMatchers().antMatchers("/login**", "/webjars/**", "/css/**", "/js/**")
        	.and()
	            .authorizeRequests()
		            .antMatchers("/login**", "/webjars/**", "/css/**", "/js/**").permitAll()
		            .anyRequest().hasAnyRole("API_USER", "ADMIN", "USER")
            .and()
            	.exceptionHandling()
					.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
	        .and()
	        	.logout()
	        		.logoutSuccessHandler(
	        				(request, response, authentication) -> {
	        					LOG.debug("clear security context");
	        					new RestTemplate().postForObject("http://localhost:9095/auth/logout", null, String.class);
	        					
	        					HttpSession session = request.getSession(false);
	        					for(Cookie cookie : request.getCookies()){
	        						LOG.debug("remove cookie["+cookie.getName()+":"+cookie.getValue()+"]");
	        						cookie.setValue(null);
	        						cookie.setMaxAge(0);
	        						response.addCookie(cookie);
	        					}
	        					LOG.debug("httpSession:" + session);
	        					if(session != null){
	        						LOG.debug("httpsession removeAttribute");
	        						session.removeAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
	        						session.invalidate();
	        					}
	        					LOG.debug("clear security context" + session);
	        					restTemplate().postForObject("http://localhost:9095/auth/logout", null, String.class);
	        				}
	        			)
	        .and()
	        	.csrf()      
	            .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
	//            .ignoringAntMatchers("/logout")
	        .and()
	        	.headers()
	        		.frameOptions().sameOrigin()
	        		.contentTypeOptions().disable()
	        .and()
	         	.addFilterBefore(ssoFilter(), BasicAuthenticationFilter.class)
	         	
            ;
    }

    @Override 
    public void configure(WebSecurity web) throws Exception { 
         web.ignoring().antMatchers("/resources/**", "/static/**", "/webjars/**", "/images/**"); 
    } 
    
    @Value("${cloudms.security.client.oauth2.resource-details.client.grantType}") private String grantType;
     

    @Bean
    @ConfigurationProperties("cloudms.security.client.oauth2.resource-details.client")
    public OAuth2ProtectedResourceDetails apiClient() {
    	LOG.debug("grantType:" + grantType);
    	if("password".equalsIgnoreCase(grantType)){
    		return new ResourceOwnerPasswordResourceDetails();
    	}else if("authorization_code".equalsIgnoreCase(grantType)){
    		return new AuthorizationCodeResourceDetails();
    	}else if("client_credentials".equalsIgnoreCase(grantType)){
    		return new ClientCredentialsResourceDetails();
    	}else{
    		return new BaseOAuth2ProtectedResourceDetails();
    	}
    }
    
    
    @Bean
    @Primary
    @ConfigurationProperties("cloudms.security.client.oauth2.resource-details.resource")
    public ResourceServerProperties apiResource() {
    	LOG.debug("api.resource init start");
    	return new ResourceServerProperties();
    }
    
    @Bean
    @Primary
//    public UserInfoTokenServices tokenServices(){
    public UserInfoTokenServices userInfoTokenServices(){
    	UserInfoTokenServices tokenServices = new UserInfoTokenServices(
    			apiResource().getUserInfoUri(), apiClient().getClientId());
    	tokenServices.setRestTemplate(restTemplate());
    	return tokenServices;
    }
    	      
    @Bean
	public FilterRegistrationBean oauth2ClientFilterRegistration( OAuth2ClientContextFilter filter) {
		FilterRegistrationBean registration = new FilterRegistrationBean();
		registration.setFilter(filter);
		registration.setOrder(-100);
		return registration;
	}	 
    
    private Filter ssoFilter() {
    	if(isDebug){
    		LOG.debug("successurl:" + successUrl);
    	}
    	OAuth2ClientAuthenticationProcessingFilter filter = new OAuth2ClientAuthenticationProcessingFilter("/login");
    	filter.setRestTemplate(restTemplate());
    	filter.setTokenServices(userInfoTokenServices());
    	  
    	SavedRequestAwareAuthenticationSuccessHandler handler = new SavedRequestAwareAuthenticationSuccessHandler();
    	handler.setAlwaysUseDefaultTargetUrl(false);
    	handler.setDefaultTargetUrl(successUrl);
    	
    	filter.setAuthenticationSuccessHandler(handler);
    	return filter;
    }
    
    @Autowired private OAuth2ClientContext oauth2ClientContext; 
    @Autowired private RestTemplateBuilder builder; 
    
	@Bean
	@Primary
	public OAuth2RestTemplate restTemplate() {
    	return builder
    	.configure(new OAuth2RestTemplate(apiClient(), oauth2ClientContext));
    }
	
	
	
}
