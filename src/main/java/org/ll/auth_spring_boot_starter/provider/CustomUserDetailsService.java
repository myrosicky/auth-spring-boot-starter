package org.ll.auth_spring_boot_starter.provider;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import org.ll.auth_spring_boot_starter.model.TmpUser;
import org.ll.auth_spring_boot_starter.model.UserDetailProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.StringUtils;

public class CustomUserDetailsService implements UserDetailsService {

	private final static Logger LOG = LoggerFactory.getLogger(CustomUserDetailsService.class);
	private boolean isDebug = LOG.isDebugEnabled();
	
	private Map<String, LocalDateTime> userCache = new HashMap<>();
	
	@Autowired private UserDetailProperties userDetailProperties;
	
	@Override
	public UserDetails loadUserByUsername(String username)
			throws UsernameNotFoundException {
		if(StringUtils.isEmpty(StringUtils.trimWhitespace(username))){
			return null;
		}
		Optional<TmpUser> rtn = userDetailProperties.getUsers().stream()
				.filter(username::equals)
				.findFirst()
				;
		if(!rtn.isPresent()){
			return null;
		}
		TmpUser tmpUser = rtn.get();
		if(StringUtils.isEmpty(tmpUser.getLastLoginTime())){
			tmpUser.setLastLoginTime(LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS")));
		}
		return tmpUser;
	}

}
