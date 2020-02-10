package org.ll.auth_spring_boot_starter.config;

import org.business.exceptions.CallApiException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.cloud.openfeign.EnableFeignClients;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;

import feign.RequestInterceptor;
import feign.codec.ErrorDecoder;

@Configuration
@ConditionalOnProperty("security.feign.enabled")
@EnableFeignClients(basePackages={"${security.feign.basePackages}"})
public class FeignConfig {

	private static final Logger LOG = LoggerFactory.getLogger(FeignConfig.class);
	private boolean isDebug = LOG.isDebugEnabled();
	
	@Bean
	@ConditionalOnProperty("security.feign.oauth2.enabled")
	@Lazy
	public RequestInterceptor oauth2RequestInterceptor(OAuth2ClientContext oauth2ClientContext){
		if(isDebug){
			LOG.debug("init custom oauth2RequestInterceptor");
		}
		return (template) -> template.header(HttpHeaders.AUTHORIZATION, 
						String.format("%s %s", 
								oauth2ClientContext.getAccessToken() != null? oauth2ClientContext.getAccessToken().getTokenType():"", 
								oauth2ClientContext.getAccessToken() != null? oauth2ClientContext.getAccessToken().getValue():""
						)
					)
		;
	}
	
	 @Bean
	 @ConditionalOnProperty("security.feign.oauth2.enabled")
	 @Lazy
	 public ErrorDecoder errorDecoder(final OAuth2RestTemplate restTemplate) {
	     return (methodKey, response) ->{
	    	 if(isDebug){
	    		 LOG.debug("response.status():" + response.status());
	    	 }
				if(response.status() == HttpStatus.UNAUTHORIZED.value()){
					LOG.debug("refresh token now");
					restTemplate.getAccessToken();
					return null;
				}
//				return errorStatus(methodKey, response);
				return new CallApiException(methodKey);
		}
	    ;
	 }
	
}
