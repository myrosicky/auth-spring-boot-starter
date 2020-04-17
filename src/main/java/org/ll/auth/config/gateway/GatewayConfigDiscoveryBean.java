package org.ll.auth.config.gateway;

import java.util.List;

import lombok.Data;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Data
@ConfigurationProperties("cloudms.gateway")
@Configuration
public class GatewayConfigDiscoveryBean {

	private List<String> ignoredServices;
}
