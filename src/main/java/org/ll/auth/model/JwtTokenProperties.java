package org.ll.auth.model;

import lombok.Data;

@Data
public class JwtTokenProperties {
	
	private KeystoreProperties signer;
	private KeystoreProperties verifier;
	
}
