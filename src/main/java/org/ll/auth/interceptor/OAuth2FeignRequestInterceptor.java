package org.ll.auth.interceptor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.util.Assert;

import feign.RequestInterceptor;
import feign.RequestTemplate;

public class OAuth2FeignRequestInterceptor implements RequestInterceptor {

	private static final Logger LOG = LoggerFactory.getLogger(OAuth2FeignRequestInterceptor.class);
	private boolean isDebug = LOG.isDebugEnabled();
	
	private static final String AUTHORIZATION_HEADER = "Authorization";
	
	private static final String BEARER_TOKEN_TYPE = "Bearer";
	
	private final OAuth2RestTemplate oauth2RestTemplate;
	
	public OAuth2FeignRequestInterceptor(OAuth2RestTemplate oauth2RestTemplate){
		Assert.notNull(oauth2RestTemplate, "restTemplate cannot be null");
		this.oauth2RestTemplate = oauth2RestTemplate;
	}
	
	@Override
	public void apply(RequestTemplate template) {
		LOG.debug("constructing Header {} for token {}", AUTHORIZATION_HEADER, BEARER_TOKEN_TYPE);
		template.header(AUTHORIZATION_HEADER, String.format("%s %s", BEARER_TOKEN_TYPE, oauth2RestTemplate.getAccessToken().toString()));
	}

}
