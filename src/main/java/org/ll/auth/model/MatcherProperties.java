package org.ll.auth.model;

import lombok.Data;

import org.springframework.http.HttpMethod;
import org.springframework.util.StringUtils;

@Data
public class MatcherProperties {

	private String pattern;
	private String attribute;
	private String type;
	private HttpMethod httpMethod;
	private String hasAuthority;
	
//	public HttpMethod getMethod(){
//		return HttpMethod.valueOf(StringUtils.uncapitalize(httpMethod));
//	}
	
	
}
