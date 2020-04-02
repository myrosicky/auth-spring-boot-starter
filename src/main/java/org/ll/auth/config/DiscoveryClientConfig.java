package org.ll.auth.config;

import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.actuate.health.OrderedHealthAggregator;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.SearchStrategy;
import org.springframework.cloud.health.RefreshScopeHealthIndicator;
import org.springframework.cloud.netflix.eureka.EurekaClientConfigBean;
import org.springframework.cloud.netflix.eureka.EurekaHealthCheckHandler;
import org.springframework.cloud.netflix.eureka.EurekaInstanceConfigBean;
import org.springframework.cloud.netflix.hystrix.HystrixHealthIndicator;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.StringUtils;

import com.netflix.appinfo.EurekaInstanceConfig;
import com.netflix.appinfo.HealthCheckHandler;
import com.netflix.discovery.EurekaClientConfig;


@Configuration
@ConditionalOnProperty("cloudms.discovery.auto-config.enabled")
@AutoConfigureAfter(name = {
		"org.springframework.cloud.netflix.eureka.EurekaClientAutoConfiguration"})
public class DiscoveryClientConfig {

	private static final Logger LOG = LoggerFactory.getLogger(DiscoveryClientConfig.class);
	private boolean isDebug = LOG.isDebugEnabled();
	
	;

	@Bean
	@ConditionalOnBean(value = EurekaClientConfig.class, search = SearchStrategy.CURRENT)
	public Integer configureEurekaClient(EurekaClientConfigBean eurekaClientConfigBean,
			@Value("${cloudms.discovery.auto-config.defaultZone:''}") String defaultZone
			){
		LOG.debug("init custom EurekaClientConfigBean");
		Map<String, String> serviceUrl = eurekaClientConfigBean.getServiceUrl();
		if(isDebug){
			LOG.debug("before eurekaClientConfigBean.getServiceUrl():" + serviceUrl);
		}
		if(serviceUrl == null || serviceUrl.isEmpty()){
			serviceUrl = new HashMap<>();
		}
		if(StringUtils.hasLength(defaultZone)){
			String existingZone = serviceUrl.get(EurekaClientConfigBean.DEFAULT_ZONE);
	//		serviceUrl.put(EurekaClientConfigBean.DEFAULT_ZONE, "http://localhost:8761/eureka-server-0.0.1"+EurekaConstants.DEFAULT_PREFIX+", http://localhost:8761"+EurekaConstants.DEFAULT_PREFIX+", http://localhost:8762"+EurekaConstants.DEFAULT_PREFIX);
			existingZone = defaultZone + (StringUtils.hasLength(existingZone) ? (", " + existingZone) : "");
			serviceUrl.put(EurekaClientConfigBean.DEFAULT_ZONE,  existingZone);
			eurekaClientConfigBean.setServiceUrl(serviceUrl);
		}
		return 1;
	}
	
	
	@Bean
	@ConditionalOnBean(value = EurekaInstanceConfig.class, search = SearchStrategy.CURRENT)
	public Integer configureEurekaInstance(EurekaInstanceConfigBean eurekaInstanceConfigBean,
			@Value("${spring.application.name}") String appName,
			@Value("${spring.application.instance_id:}") String instId
			){
		LOG.debug("init custom eurekaInstanceConfigBean");
		eurekaInstanceConfigBean.setInstanceId(appName + (StringUtils.hasLength(instId)? (":" + instId) : "") + ":" + Math.abs(new Random().nextLong()));
		if(isDebug){
			LOG.debug("service InstanceId:" + eurekaInstanceConfigBean.getInstanceId());
		}
		return 1;
	}
	
	@Bean
	@ConditionalOnMissingBean(value = HealthCheckHandler.class, search = SearchStrategy.CURRENT)
	public HealthCheckHandler healthCheckHandler(ApplicationContext context, 
//			DiskSpaceHealthIndicator diskSpaceHealthIndicator, 
			RefreshScopeHealthIndicator refreshScopeHealthIndicator, 
			HystrixHealthIndicator hystrixHealthIndicator){
		if(isDebug){
//			LOG.debug("custome healthCheckHandler: diskSpaceHealthIndicator:" + diskSpaceHealthIndicator);
			LOG.debug("custome healthCheckHandler: refreshScopeHealthIndicator:" + refreshScopeHealthIndicator);
			LOG.debug("custome healthCheckHandler: hystrixHealthIndicator:" + hystrixHealthIndicator);
		}
		EurekaHealthCheckHandler rtn = new EurekaHealthCheckHandler(new OrderedHealthAggregator());
		rtn.setApplicationContext(context);
		return rtn;
	}
}
