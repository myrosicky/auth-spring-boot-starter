package org.ll.auth_spring_boot_starter.model;

import java.util.List;

import lombok.Data;

@Data
public class AuthorizeReqProperties {

	private List<MatcherProperties> matchers;
	
}
