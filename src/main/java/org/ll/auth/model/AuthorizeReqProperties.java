package org.ll.auth.model;

import java.util.List;

import lombok.Data;

@Data
public class AuthorizeReqProperties {

	private List<MatcherProperties> matchers;
	
}
