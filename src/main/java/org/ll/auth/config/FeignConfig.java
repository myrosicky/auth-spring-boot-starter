package org.ll.auth.config;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.stream.Collectors;

import org.ll.auth.exception.CallApiException;
import org.ll.auth.processor.feign.RequestBodyParameterProcessor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.cloud.netflix.ribbon.SpringClientFactory;
import org.springframework.cloud.openfeign.EnableFeignClients;
import org.springframework.cloud.openfeign.ribbon.CachingSpringLoadBalancerFactory;
import org.springframework.cloud.openfeign.ribbon.LoadBalancerFeignClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.util.CollectionUtils;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.WebClient;

import reactor.core.publisher.Mono;
import feign.Client;
import feign.Request.HttpMethod;
import feign.RequestInterceptor;
import feign.codec.ErrorDecoder;

@Configuration
@ConditionalOnProperty("cloudms.feign.enabled")
@EnableFeignClients(basePackages={"${cloudms.feign.basePackages}"})
public class FeignConfig {

	private static final Logger LOG = LoggerFactory.getLogger(FeignConfig.class);
	
	@Bean
	@ConditionalOnProperty("cloudms.feign.oauth2.enabled")
	@Lazy
	public RequestInterceptor oauth2RequestInterceptor(OAuth2ClientContext oauth2ClientContext){
		LOG.debug("init custom oauth2RequestInterceptor");
		return (template) -> template.header(HttpHeaders.AUTHORIZATION, 
						String.format("%s %s", 
								OAuth2AccessToken.BEARER_TYPE, 
								oauth2ClientContext.getAccessToken() != null? oauth2ClientContext.getAccessToken().getValue():""
						)
					)
		;
	}
	
	 @Bean
	 @ConditionalOnProperty("cloudms.feign.oauth2.enabled")
	 @Lazy
	 public ErrorDecoder errorDecoder(final OAuth2RestTemplate restTemplate) {
	     return (methodKey, response) ->{
	    		 LOG.debug("response.status(): [{}]", response.status());
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
	 
	 @Bean
	 @ConditionalOnProperty("cloudms.feign.custom-features.enabled")
	 public RequestBodyParameterProcessor requestBodyParameterProcessor(){
		 return new RequestBodyParameterProcessor();
	 }

	 @Bean
	 @ConditionalOnProperty("cloudms.feign.reactive.enabled")
	 @Primary
	 public Client feignClient(CachingSpringLoadBalancerFactory cachingFactory,
	 		SpringClientFactory clientFactory) {
	 	return new LoadBalancerFeignClient(
	 			(req, opts) -> {
	 				LOG.debug("init custom reactive http client");
	 				WebClient delegate = WebClient.builder()
	 						.filter(logRequest())
	 						.filter(logResponse())
	 						.baseUrl(req.url())
//	 						.create(req.url())
	 						.build()
	 						;
	 				MultiValueMap<String, String> headers = 
								CollectionUtils.toMultiValueMap(
								 (Map<String, List<String>>)req.headers().entrySet().stream().collect(Collectors.toMap(Entry::getKey, entry -> entry.getValue().stream().collect(Collectors.toList())
									 ))
								)
						;
	 				Mono<ClientResponse> resp = null;

	 				if(HttpMethod.GET==req.httpMethod()){
	 					resp = delegate.get()
		 					.headers(h -> h.addAll(headers))
		 					.exchange()
	 					;
	 				}else if(HttpMethod.POST==req.httpMethod()){
	 					resp = delegate.post()
		 					.headers(h -> h.addAll(headers))
		 					.body(BodyInserters.fromObject(req.requestBody()))
		 					.exchange()
	 					;
	 				}
//	 				ClientResponse respBlock = resp.bodyToMono(ClientResponse.class).block();
	 				ClientResponse respBlock = resp.block(Duration.ofSeconds(2));
	 				
	 				LOG.debug("respBlock: [{}]", respBlock);
	 				
	 				return feign.Response.builder()
	 						.status(respBlock.statusCode().value())
	 						.body(respBlock.bodyToMono(String.class).block(), feign.Util.UTF_8) // json body
	 						.request(req)
	 						.headers(respBlock.headers().asHttpHeaders().entrySet().stream().collect(Collectors.toMap(Entry::getKey, Entry::getValue)))
	 						.build()
	 						;
		 		}, cachingFactory, clientFactory);
	 }
	 
	 private ExchangeFilterFunction logRequest() {
		    return (clientRequest, next) -> {
		    	LOG.info("Request: {} {}", clientRequest.method(), clientRequest.url());
		        clientRequest.headers()
		                .forEach((name, values) -> values.forEach(value -> LOG.info("{}={}", name, value)));
		        return next.exchange(clientRequest);
		    };
		}
	 
	 private ExchangeFilterFunction logResponse() {
		    return ExchangeFilterFunction.ofResponseProcessor(clientResponse -> {
		    	LOG.info("Response: {}", clientResponse);
		        return Mono.just(clientResponse);
		    });
		}
	 
	
}
