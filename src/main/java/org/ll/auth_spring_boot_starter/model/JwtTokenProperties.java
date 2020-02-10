package org.ll.auth_spring_boot_starter.model;

import lombok.Data;

@Data
public class JwtTokenProperties {
	
	private KeystoreProperties signer;
	private KeystoreProperties verifier;
	
}
