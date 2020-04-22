package org.ll.auth.config.gateway;

import static org.springframework.cloud.gateway.filter.factory.RewritePathGatewayFilterFactory.REGEXP_KEY;
import static org.springframework.cloud.gateway.filter.factory.RewritePathGatewayFilterFactory.REPLACEMENT_KEY;
import static org.springframework.cloud.gateway.handler.predicate.RoutePredicateFactory.PATTERN_KEY;
import static org.springframework.cloud.gateway.support.NameUtils.normalizeFilterFactoryName;
import static org.springframework.cloud.gateway.support.NameUtils.normalizeRoutePredicateName;

import java.time.Duration;
import java.util.ArrayList;

import javax.annotation.Resource;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.cloud.client.discovery.DiscoveryClient;
import org.springframework.cloud.gateway.config.HttpClientProperties;
import org.springframework.cloud.gateway.discovery.DiscoveryClientRouteDefinitionLocator;
import org.springframework.cloud.gateway.discovery.DiscoveryLocatorProperties;
import org.springframework.cloud.gateway.filter.FilterDefinition;
import org.springframework.cloud.gateway.filter.factory.RewritePathGatewayFilterFactory;
import org.springframework.cloud.gateway.handler.predicate.PathRoutePredicateFactory;
import org.springframework.cloud.gateway.handler.predicate.PredicateDefinition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

@Configuration
@ConditionalOnProperty("cloudms.gateway.spring-cloud.enabled")
public class GatewayConfig {

	private static final Logger log = LoggerFactory.getLogger(GatewayConfig.class);
	
	@Resource private GatewayConfigDiscoveryBean gatewayConfigDiscoveryBean;
//	@Bean
//	public PatternServiceRouteMapper serviceRouteMapper(){
//		// api application name: api-v1 to v1/api 
//		return new PatternServiceRouteMapper(
//				 "(?<name>^.+)-(?<version>v.+$)",
//		        "${version}/${name}"
//		);
//	} 


	@Bean
	@ConditionalOnBean(DiscoveryClient.class)
	@ConditionalOnProperty(name = "cloudms.gateway.spring-cloud.discovery.enabled")
	public DiscoveryClientRouteDefinitionLocator customDiscoveryClientRouteDefinitionLocator(
			DiscoveryClient discoveryClient, DiscoveryLocatorProperties properties) {
		return new DiscoveryClientRouteDefinitionLocator(discoveryClient, properties);
	}
	
	@Bean
	@Primary
	@ConditionalOnProperty("cloudms.gateway.spring-cloud.discovery.enabled")
	public DiscoveryLocatorProperties customDiscoveryLocatorProperties() {
		log.debug("init custom discoveryLocatorProperties");
		DiscoveryLocatorProperties properties = new DiscoveryLocatorProperties();
		properties.setEnabled(true);
		
//		properties.setPredicates(GatewayDiscoveryClientAutoConfiguration.initPredicates());
//		properties.setFilters(GatewayDiscoveryClientAutoConfiguration.initFilters());
		properties.setPredicates(new ArrayList<PredicateDefinition>());
		properties.setFilters(new ArrayList<FilterDefinition>());
		
		properties.setLowerCaseServiceId(true);
		// ignore services
		log.debug("ignoreServices: [{}]", gatewayConfigDiscoveryBean.getIgnoredServices());
		StringBuilder includeExpression = new StringBuilder(50);
		gatewayConfigDiscoveryBean.getIgnoredServices().forEach(service -> {
			includeExpression.append(" serviceId.equalsIgnoreCase('" + service + "') ||");
		});
		includeExpression.delete(includeExpression.length()-2, includeExpression.length()).append("? false:true");
		log.debug("includeExpression:[{}]", includeExpression);
		properties.setIncludeExpression(includeExpression.toString());
		
		// convert path by service id 
		String spelStr = "(serviceId.indexOf('-v') > -1 ? (serviceId.substring(serviceId.lastIndexOf('-v')+1) + '/' +  serviceId.substring(0, serviceId.lastIndexOf('-v'))) : serviceId)";
		PredicateDefinition predicate = new PredicateDefinition();
		predicate.setName(normalizeRoutePredicateName(PathRoutePredicateFactory.class)); // Path
		predicate.addArg(PATTERN_KEY, "'/'+ " + spelStr + " +'/**'");
		properties.getPredicates().add(predicate);
		
		FilterDefinition filter = new FilterDefinition();
		filter.setName(normalizeFilterFactoryName(RewritePathGatewayFilterFactory.class));
		String regex = "'/' + " + spelStr + " + '/(?<remaining>.*)'";
		String replacement = "'/${remaining}'";
		filter.addArg(REGEXP_KEY, regex);
		filter.addArg(REPLACEMENT_KEY, replacement);
		properties.getFilters().add(filter);
		
		return properties;
	}
	
	@Bean
	@Primary
	public HttpClientProperties customHttpClientProperties(){
		log.debug("init custom HttpClientProperties");
		// set global timeout
		HttpClientProperties httpClientProperties = new HttpClientProperties();
		httpClientProperties.setConnectTimeout(10000);
		httpClientProperties.setResponseTimeout(Duration.ofSeconds(5));
		return httpClientProperties;
	}
	
	
	
//	@Bean
//	public RouteLocator customRouteLocator(RouteLocatorBuilder builder) {
//		//@formatter:off
//		// String uri = "http://httpbin.org:80";
//		// String uri = "http://localhost:9080";
//		return builder.routes().build();
////		return builder.routes()
////				.route(r -> r.host("**.abc.org").and().path("/anything/png")
////					.filters(f ->
////							f.prefixPath("/httpbin")
////									.addResponseHeader("X-TestHeader", "foobar"))
////					.uri(uri)
////				)
////				.route("read_body_pred", r -> r.host("*.readbody.org")
////						.and().readBody(String.class,
////										s -> s.trim().equalsIgnoreCase("hi"))
////					.filters(f -> f.prefixPath("/httpbin")
////							.addResponseHeader("X-TestHeader", "read_body_pred")
////					).uri(uri)
////				)
////				.route("rewrite_request_obj", r -> r.host("*.rewriterequestobj.org")
////					.filters(f -> f.prefixPath("/httpbin")
////							.addResponseHeader("X-TestHeader", "rewrite_request")
////							.modifyRequestBody(String.class, Hello.class, MediaType.APPLICATION_JSON_VALUE,
////									(exchange, s) -> {
////										return Mono.just(new Hello(s.toUpperCase()));
////									})
////					).uri(uri)
////				)
////				.route("rewrite_request_upper", r -> r.host("*.rewriterequestupper.org")
////					.filters(f -> f.prefixPath("/httpbin")
////							.addResponseHeader("X-TestHeader", "rewrite_request_upper")
////							.modifyRequestBody(String.class, String.class,
////									(exchange, s) -> {
////										return Mono.just(s.toUpperCase() + s.toUpperCase());
////									})
////					).uri(uri)
////				)
////				.route("rewrite_response_upper", r -> r.host("*.rewriteresponseupper.org")
////					.filters(f -> f.prefixPath("/httpbin")
////							.addResponseHeader("X-TestHeader", "rewrite_response_upper")
////							.modifyResponseBody(String.class, String.class,
////									(exchange, s) -> {
////										return Mono.just(s.toUpperCase());
////									})
////					).uri(uri)
////				)
////				.route("rewrite_empty_response", r -> r.host("*.rewriteemptyresponse.org")
////					.filters(f -> f.prefixPath("/httpbin")
////							.addResponseHeader("X-TestHeader", "rewrite_empty_response")
////							.modifyResponseBody(String.class, String.class,
////									(exchange, s) -> {
////										if (s == null) {
////											return Mono.just("emptybody");
////										}
////										return Mono.just(s.toUpperCase());
////									})
////
////					).uri(uri)
////				)
////				.route("rewrite_response_fail_supplier", r -> r.host("*.rewriteresponsewithfailsupplier.org")
////					.filters(f -> f.prefixPath("/httpbin")
////							.addResponseHeader("X-TestHeader", "rewrite_response_fail_supplier")
////							.modifyResponseBody(String.class, String.class,
////									(exchange, s) -> {
////										if (s == null) {
////											return Mono.error(new IllegalArgumentException("this should not happen"));
////										}
////										return Mono.just(s.toUpperCase());
////									})
////					).uri(uri)
////				)
////				.route("rewrite_response_obj", r -> r.host("*.rewriteresponseobj.org")
////					.filters(f -> f.prefixPath("/httpbin")
////							.addResponseHeader("X-TestHeader", "rewrite_response_obj")
////							.modifyResponseBody(Map.class, String.class, MediaType.TEXT_PLAIN_VALUE,
////									(exchange, map) -> {
////										Object data = map.get("data");
////										return Mono.just(data.toString());
////									})
////							.setResponseHeader("Content-Type", MediaType.TEXT_PLAIN_VALUE)
////					).uri(uri)
////				)
////				.route(r -> r.path("/image/webp")
////					.filters(f ->
////							f.prefixPath("/httpbin")
////									.addResponseHeader("X-AnotherHeader", "baz"))
////					.uri(uri)
////				)
////				.route(r -> r.order(-1)
////					.host("**.throttle.org").and().path("/get")
////					.filters(f -> f.prefixPath("/httpbin")
////									.filter(new ThrottleGatewayFilter()
////									.setCapacity(1)
////									.setRefillTokens(1)
////									.setRefillPeriod(10)
////									.setRefillUnit(TimeUnit.SECONDS)))
////					.uri(uri)
////				)
////				.build();
//		//@formatter:on
//	}

//	@Bean
//	public RouterFunction<ServerResponse> testFunRouterFunction() {
//		RouterFunction<ServerResponse> route = RouterFunctions.route(
//				RequestPredicates.path("/testfun"),
//				request -> ServerResponse.ok().body(BodyInserters.fromObject("hello")));
//		return route;
//	}
//
//	@Bean
//	public RouterFunction<ServerResponse> testWhenMetricPathIsNotMeet() {
//		RouterFunction<ServerResponse> route = RouterFunctions.route(
//				RequestPredicates.path("/actuator/metrics/gateway.requests"),
//				request -> ServerResponse.ok().body(BodyInserters
//						.fromObject(HELLO_FROM_FAKE_ACTUATOR_METRICS_GATEWAY_REQUESTS)));
//		return route;
//	}
//
//	static class Hello {
//
//		String message;
//
//		Hello() {
//		}
//
//		Hello(String message) {
//			this.message = message;
//		}
//
//		public String getMessage() {
//			return message;
//		}
//
//		public void setMessage(String message) {
//			this.message = message;
//		}
//
//	}
	
}