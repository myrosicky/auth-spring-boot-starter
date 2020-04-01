package org.ll.auth.model;

import java.util.Set;

import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

public class CustomClientDetails extends BaseClientDetails {

	private static final long serialVersionUID = 1L;
	
	private Set<String> authoritiesAsString;
	

	public Set<String> getAuthoritiesAsString() {
		return authoritiesAsString;
	}


	public void setAuthoritiesAsString(Set<String> authoritiesAsString) {
		this.authoritiesAsString = authoritiesAsString;
		setAuthorities(AuthorityUtils.createAuthorityList(authoritiesAsString
				.toArray(new String[authoritiesAsString.size()])));
	}

}
