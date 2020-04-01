package org.ll.auth.model;

import lombok.Data;

@Data
public class KeystoreProperties {

	private boolean enabled;
	private String keyStoreType;
	private String keyStore;
	private String keyStorePwd;
	private String keyAlias;
	private String algorithm;
}
