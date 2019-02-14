package com.fortunato.twoFactorAuth.model;

public class AuthModel {

	private String qrCode;
	private String key;
	private byte[] secret;
	private String encoded;
	private String host;
	
	public String getQrCode() {
		return qrCode;
	}
	public void setQrCode(String qrCode) {
		this.qrCode = qrCode;
	}
	public String getKey() {
		return key;
	}
	public void setKey(String key) {
		this.key = key;
	}
	public byte[] getSecret() {
		return secret;
	}
	public void setSecret(byte[] secret2) {
		this.secret = secret2;
	}
	public String getHost() {
		return host;
	}
	public void setHost(String host) {
		this.host = host;
	}
	public String getEncoded() {
		return encoded;
	}
	public void setEncoded(String encoded) {
		this.encoded = encoded;
	}
}
