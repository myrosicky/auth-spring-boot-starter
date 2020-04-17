package org.ll.auth.model;

import lombok.Data;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Data
public class JwtTokenProperties {
	
	private KeystoreProperties signer;
	private KeystoreProperties verifier;
	
}
