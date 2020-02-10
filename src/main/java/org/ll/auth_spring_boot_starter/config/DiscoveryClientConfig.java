package org.ll.auth_spring_boot_starter.config;

import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.actuate.health.OrderedHealthAggregator;
import org.springframework.boot.actuate.system.DiskSpaceHealthIndicator;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.cloud.health.RefreshScopeHealthIndicator;
import org.springframework.cloud.netflix.eureka.EurekaClientConfigBean;
import org.springframework.cloud.netflix.eureka.EurekaHealthCheckHandler;
import org.springframework.cloud.netflix.eureka.EurekaHealthIndicator;
import org.springframework.cloud.netflix.hystrix.HystrixHealthIndicator;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

import com.netflix.appinfo.HealthCheckHandler;

@Configuration
@ConditionalOnProperty("security.discovery.auto-config.enabled")
public class DiscoveryClientConfig {

	private static final Logger LOG = LoggerFactory.getLogger(DiscoveryClientConfig.class);
	private boolean isDebug = LOG.isDebugEnabled();
	
	@Bean
	@Primary
	public EurekaClientConfigBean eurekaClientConfig(){
		EurekaClientConfigBean bean = new EurekaClientConfigBean();
		Map<String, String> serviceUrl = new HashMap<>();
		serviceUrl.put(EurekaClientConfigBean.DEFAULT_ZONE, "http://localhost:8761/eureka, http://localhost:8762/eureka");
		bean.setServiceUrl(serviceUrl);
		return bean;
	}
	
	@Bean
	@Primary
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
