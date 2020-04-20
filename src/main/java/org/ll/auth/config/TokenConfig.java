package org.ll.auth.config;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPublicKey;
import java.util.LinkedHashMap;
import java.util.Map;

import org.ll.auth.model.JwtTokenProperties;
import org.ll.auth.model.KeystoreProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.jwt.crypto.sign.InvalidSignatureException;
import org.springframework.security.jwt.crypto.sign.SignatureVerifier;
import org.springframework.security.jwt.crypto.sign.Signer;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

@Configuration
@ConditionalOnProperty("cloudms.security.token.enabled")
@Order(1)
public class TokenConfig {
	
	private static final Logger LOG = LoggerFactory.getLogger(TokenConfig.class);
	private boolean isDebug = LOG.isDebugEnabled();
	
	@Bean
	@ConfigurationProperties("cloudms.security.token.jwt")
	public JwtTokenProperties jwtTokenProperties(){
		return new JwtTokenProperties();
	}

	@Configuration
	@ConditionalOnProperty(value = "cloudms.security.token.servlet-features", matchIfMissing = true)
	public class ServletFeatures{
		
		@Bean
		public TokenEnhancer tokenEnhancer(){
			return (accessToken, authentication) -> {
				DefaultOAuth2AccessToken result = new DefaultOAuth2AccessToken(accessToken); 
				Map<String, Object> info = new LinkedHashMap<>(accessToken.getAdditionalInformation());
				info.put("haha", "valueInputByEnhancer");
				result.setAdditionalInformation(info);
				if(isDebug){
					LOG.debug("tokenEnhancer - authentication:" + authentication);
					LOG.debug("tokenEnhancer - authentication.getUserAuthentication():" + authentication.getUserAuthentication());
					LOG.debug("tokenEnhancer - authentication.getDetails():" + authentication.getDetails());
				}
				return result;
			};
	 	} 
		
		@Bean
		public JwtAccessTokenConverter tokenConverter(){
			LOG.debug("init accessTokenConverter start");
			JwtAccessTokenConverter jwtTokenEnhancer = new JwtAccessTokenConverter();
			JwtTokenProperties tokenProperties = jwtTokenProperties();
			KeystoreProperties signer = tokenProperties.getSigner();
			if(signer != null && signer.isEnabled()){
				if(isDebug){
					LOG.debug("signer.getAlgorithm():" + signer.getAlgorithm());
					LOG.debug("signer.getKeyAlias():" + signer.getKeyAlias());
					LOG.debug("signer.getKeyStore():" + signer.getKeyStore());
					LOG.debug("signer.getKeyStorePwd():" + signer.getKeyStorePwd());
					LOG.debug("signer.getKeyStoreType():" + signer.getKeyStoreType());
				}
				jwtTokenEnhancer.setSigner(new Signer(){
					@Override
					public String algorithm() {
						return signer.getAlgorithm();
					}
		
					@Override
					public byte[] sign(byte[] bytes) {
						
						try {
							KeyStoreKeyFactory keystore = new KeyStoreKeyFactory(new ClassPathResource(signer.getKeyStore()), signer.getKeyStorePwd().toCharArray());
							PrivateKey privateKey = keystore.getKeyPair(signer.getKeyAlias()).getPrivate();
							Signature sig = Signature.getInstance(algorithm());
							sig.initSign(privateKey);
							sig.update(bytes);
							return sig.sign();
						} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
							LOG.error("", e);
						}
						return bytes;
					}
					
				});
			}
			
			KeystoreProperties verifier = tokenProperties.getVerifier();
			if(verifier != null && verifier.isEnabled()){
				if(isDebug){
					LOG.debug("init accessTokenConverter start");
					LOG.debug("verifier.getAlgorithm():" + verifier.getAlgorithm());
					LOG.debug("verifier.getKeyAlias():" + verifier.getKeyAlias());
					LOG.debug("verifier.getKeyStore():" + verifier.getKeyStore());
					LOG.debug("verifier.getKeyStorePwd():" + verifier.getKeyStorePwd());
					LOG.debug("verifier.getKeyStoreType():" + verifier.getKeyStoreType());
				}
				jwtTokenEnhancer.setVerifier(new SignatureVerifier(){

					@Override
					public String algorithm() {
						return verifier.getAlgorithm();
					}

					@Override
					public void verify(byte[] content, byte[] signature) {
						try {
							KeyStore keystore = KeyStore.getInstance(verifier.getKeyStoreType());
							keystore.load(new ClassPathResource(verifier.getKeyStore()).getInputStream(), verifier.getKeyStorePwd().toCharArray());
							Certificate cert = keystore.getCertificate(verifier.getKeyAlias());
							Signature sig = Signature.getInstance(algorithm());
							sig.initVerify(cert);
							sig.update(content);
							if(!sig.verify(signature)){
								throw new InvalidSignatureException("Signature did not match content");
							}
						} catch (KeyStoreException
								| NoSuchAlgorithmException | CertificateException
								| IOException | InvalidKeyException | SignatureException e) {
							LOG.error("", e);
						}
						
					}
					
				});
			}

			LOG.debug("init accessTokenConverter end");
			return jwtTokenEnhancer;
		}
		
		@Bean
		@Primary
		public TokenStore tokenStore(){
			return new JwtTokenStore(tokenConverter());
		}
		
		@Bean
		@Primary
		// Making this primary to avoid any accidental duplication with other
		// token service instance of the same name
		public DefaultTokenServices tokenServices(){
			DefaultTokenServices tokenServices = new DefaultTokenServices();
			tokenServices.setTokenStore(tokenStore());
			tokenServices.setTokenEnhancer(tokenEnhancer());
			tokenServices.setReuseRefreshToken(true);
			return tokenServices;
		}
	}
	
	

}
