package org.ll.auth.config.dataaccess;


import java.util.Properties;

import javax.persistence.EntityManagerFactory;
import javax.sql.DataSource;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportResource;
import org.springframework.context.annotation.Primary;
import org.springframework.orm.hibernate5.HibernateExceptionTranslator;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.orm.jpa.vendor.HibernateJpaVendorAdapter;
import org.springframework.transaction.PlatformTransactionManager;

@Configuration
@ImportResource({"${cloudms.dataaccess.jpa.import-resource}"})
@ConditionalOnProperty("cloudms.dataaccess.jpa.enabled")
public class DataAccessConfig {
	
	private final static Logger log = LoggerFactory.getLogger(DataAccessConfig.class);
	
	
	@Autowired
	private DataSource dataSource;
	
	@Value("${cloudms.dataaccess.jpa.hibernate.ddl-auto}")
	private String ddlAuto;
	
	@Value("${cloudms.dataaccess.jpa.hibernate.packageToScan}")
	private String packageToScan;

	@Value("${cloudms.dataaccess.jpa.hibernate.dialect}")
	private String dialect;
	
	@Bean
	public HibernateJpaVendorAdapter hibernateJpaVendorAdapter(){
		HibernateJpaVendorAdapter hibernateJpaVendorAdapter = new HibernateJpaVendorAdapter();
		hibernateJpaVendorAdapter.setGenerateDdl(true);
		hibernateJpaVendorAdapter.setShowSql(true);
		return hibernateJpaVendorAdapter;
	}
	
	@Bean
	public EntityManagerFactory entityManagerFactory() {
		log.info("hibernate packageToScan:" + packageToScan);
		log.info("hibernate hibernate.hbm2ddl.auto:" + ddlAuto);
		log.info("hibernate hibernate.dialect:" + dialect);
		
		LocalContainerEntityManagerFactoryBean emf = new LocalContainerEntityManagerFactoryBean();
		emf.setDataSource(dataSource);
		emf.setPackagesToScan(packageToScan);
		emf.setJpaVendorAdapter(hibernateJpaVendorAdapter());

		Properties properties = new Properties();
		properties.setProperty("hibernate.hbm2ddl.auto", ddlAuto);
		properties.setProperty("hibernate.dialect", dialect);
//		properties.setProperty("hibernate.physical_naming_strategy", "org.stockws.context.ArchivePhysicalNamingStrategyImpl");

		emf.setJpaProperties(properties);
		emf.afterPropertiesSet();
		EntityManagerFactory result = emf.getObject();
		return result;
	}
	
	@Bean
	@Primary
	@ConditionalOnProperty("cloudms.dataaccess.jpa.create-transaction-manager")
	public PlatformTransactionManager transactionManager() {
		JpaTransactionManager txManager = new JpaTransactionManager();
		txManager.setEntityManagerFactory(entityManagerFactory());
		return txManager;
	}

	@Bean
	public HibernateExceptionTranslator hibernateExceptionTranslator() {
		return new HibernateExceptionTranslator();
	}

}
