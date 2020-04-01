package org.ll.auth.util;

import java.util.Arrays;

import org.ll.auth.model.AuthorizeReqProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.config.annotation.web.AbstractRequestMatcherRegistry;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.util.StringUtils;

public class AntMatcherUtil {
	
	private static final Logger log = LoggerFactory.getLogger(AntMatcherUtil.class);
	private final static boolean isDebug = log.isDebugEnabled();
	
	public static String[] resolvePatterns(AuthorizeReqProperties authorizeReqProperties){
		if(authorizeReqProperties== null || authorizeReqProperties.getMatchers() == null){
			return null;
		}
		if(isDebug){
			log.debug("matchers:" + authorizeReqProperties.getMatchers());
		}
		return authorizeReqProperties.getMatchers()
				.stream()
					.map(m -> m.getPattern().split(","))
					.flatMap(Arrays::stream)
					.map(String::trim)
					.toArray(String[]::new)
		;
	}

	public static void setAuthorizeRequests(AbstractRequestMatcherRegistry<ExpressionUrlAuthorizationConfigurer<HttpSecurity>.AuthorizedUrl> registry, AuthorizeReqProperties authorizeReqProperties){
		if(authorizeReqProperties== null || authorizeReqProperties.getMatchers() == null){
			return;
		}
		if(isDebug){
			log.debug("matchers:" + authorizeReqProperties.getMatchers());
		}
		authorizeReqProperties.getMatchers()
				.stream()
				.forEach(m -> 
					Arrays.stream(m.getPattern().split(","))
						.map(StringUtils::trimWhitespace)
						.forEach(p -> registry.antMatchers(p).access(m.getAttribute()))
				)
				; 
	}
	
	
}
