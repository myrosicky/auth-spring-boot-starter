package org.ll.auth.model;

import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

import lombok.Data;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

@Data
public class TmpUser implements UserDetails{

	private Set<String> authoritiesAsString;
	private String password;
	private String username;
	private Set<GrantedAuthority> authorities;
	private boolean accountNonExpired;
	private boolean accountNonLocked;
	private boolean credentialNonExpired;
	private String lastLoginTime;
	private boolean enabled;
	
	@Override
	public boolean isCredentialsNonExpired() {
		return credentialNonExpired;
	}
	
	public Collection<GrantedAuthority> getAuthorities(){
		return authoritiesAsString.stream()
				.map(SimpleGrantedAuthority::new)
				.collect(Collectors.toSet())
				;
	}
	
}
