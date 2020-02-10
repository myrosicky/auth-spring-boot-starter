package org.ll.auth_spring_boot_starter.config;

import java.util.List;

import org.ll.auth_spring_boot_starter.model.UserDetailProperties;
import org.ll.auth_spring_boot_starter.provider.CustomUserDetailsService;
import org.ll.auth_spring_boot_starter.provider.UserPasswordProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.annotation.Order;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@ConditionalOnProperty("security.auth.enabled")
@Order(1)
public class AuthConfig  extends WebSecurityConfigurerAdapter{

	private final static Logger log = LoggerFactory.getLogger(AuthConfig.class);
	private final static boolean isDebug = log.isDebugEnabled();
	
	@Bean
	@ConditionalOnMissingBean(AuthenticationProvider.class)
	public UserPasswordProvider userPasswordProvider(){
		log.debug("init default userPasswordProvider");
		return new UserPasswordProvider(userDetailsProperties(), passwordEncoder());
	}
	
	@Autowired @Nullable private List<AuthenticationProvider> authenticationProviders;
	@Autowired private UserDetailsService userDetailsService;
	
	@Bean
	@Primary
	@ConditionalOnMissingBean(UserDetailsService.class)
	public UserDetailsService userDetailService(){
		log.debug("init default userDetailService");
		return new CustomUserDetailsService();
	}
	
	@Bean
	@ConfigurationProperties("security.auth.in-memory.user-detail")
    public UserDetailProperties userDetailsProperties() {
		return new UserDetailProperties();
	}
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth)
			throws Exception {
//		auth
//			.authenticationProvider(userPasswordProvider())
//			.userDetailsService(userDetailService())
//			;
		
		if(isDebug){
			log.debug("authenticationProviders:" + authenticationProviders);
			log.debug("userDetailsService:" + userDetailsService);
		}
		if(authenticationProviders != null){
			authenticationProviders.forEach(auth::authenticationProvider);
		}
		auth.userDetailsService(userDetailsService);
	}

	@Override
	public void configure(WebSecurity web) throws Exception {
		super.configure(web);
	}
	
	
	@Bean 
	public PasswordEncoder passwordEncoder(){
		log.debug("init BCryptPasswordEncoder begin");
		return new BCryptPasswordEncoder();
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		super.configure(http);
		http
				.csrf().ignoringAntMatchers("/login**")
			.and()
				.sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
				;
	}
	
	@Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
    	log.debug("init super.authenticationManagerBean begin");
        return super.authenticationManagerBean();
    }

}
