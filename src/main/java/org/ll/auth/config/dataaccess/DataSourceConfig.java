package org.ll.auth.config.dataaccess;

import javax.sql.DataSource;

import org.apache.commons.dbcp2.BasicDataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;

@Configuration
@ConditionalOnMissingBean(DataSource.class)
@ConditionalOnProperty("security.dataaccess.custom-datasource.enabled")
@Order(99)
public class DataSourceConfig {

	private static final Logger log = LoggerFactory.getLogger(DataSourceConfig.class);
	
	@Value("${security.dataaccess.custom-datasource.driverClassName}")
	private String driverClassName;

	@Value("${security.dataaccess.custom-datasource.url}")
	private String url;

	@Value("${security.dataaccess.custom-datasource.username}")
	private String username;

	@Value("${security.dataaccess.custom-datasource.password}")
	private String password;
	
	@Bean
	public DataSource dataSource() {
		if(log.isDebugEnabled()){
			log.debug("driverClassName:" + driverClassName);
			log.debug("url:" + url);
			log.debug("username:" + username);
		}
		
		BasicDataSource basicDataSource = new BasicDataSource();
		basicDataSource.setDriverClassName(driverClassName);
		basicDataSource.setUrl(url);
		basicDataSource.setUsername(username);
		basicDataSource.setPassword(password);
		return basicDataSource;
	}
}
