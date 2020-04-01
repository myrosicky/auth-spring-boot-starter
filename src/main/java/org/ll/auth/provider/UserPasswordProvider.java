package org.ll.auth.provider;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Optional;

import org.ll.auth.model.TmpUser;
import org.ll.auth.model.UserDetailProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;

public class UserPasswordProvider implements AuthenticationProvider {

	private static final Logger LOG = LoggerFactory.getLogger(UserPasswordProvider.class);
	
	private boolean isDebug = LOG.isDebugEnabled();
	
	private UserDetailProperties userDetailProperties;
	
	private PasswordEncoder passwordEncoder;
	
	public UserPasswordProvider(UserDetailProperties userDetailProperties, PasswordEncoder passwordEncoder){
		this.userDetailProperties = userDetailProperties;
		this.passwordEncoder = passwordEncoder;
	}
	
	@Override
	public Authentication authenticate(Authentication authentication)
			throws AuthenticationException {
		String username = authentication.getPrincipal().toString();
		Object credentials = authentication.getCredentials();
		String password = credentials == null? null : credentials.toString();
		if(isDebug){
			LOG.debug("login attempt -- username:" + username);
			LOG.debug("login attempt -- password:" + password);
		}
		Optional<TmpUser> optionalUser = userDetailProperties.getUsers().stream()
				.filter(u -> u.getUsername().equals(username) && passwordEncoder.matches(password, u.getPassword()))
				.findFirst()
				;
		
		if(isDebug){
			LOG.debug("optionalUser.isPresent():" + optionalUser.isPresent());
		} 
		
		if(!optionalUser.isPresent()){
			return null;
		}else{
			TmpUser tmpUser = optionalUser.get();
			tmpUser.setLastLoginTime(LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS")));
			if(isDebug){
				LOG.debug("login successfully");
				LOG.debug("tmpUser.getUsername():"+ tmpUser.getUsername());
				LOG.debug("tmpUser.getPassword():"+ tmpUser.getPassword());
				LOG.debug("tmpUser.getAuthorities():"+ tmpUser.getAuthorities());
				LOG.debug("tmpUser.getLastLoginTime():"+ tmpUser.getLastLoginTime());
			}
			UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(tmpUser, tmpUser.getPassword(), tmpUser.getAuthorities());
			auth.setDetails(tmpUser);
			return auth;
		}
		
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
	}

}
