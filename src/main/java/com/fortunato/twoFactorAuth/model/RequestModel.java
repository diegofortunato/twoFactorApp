package com.fortunato.twoFactorAuth.model;

public class RequestModel {

	private byte[] secret;
	private String code;
	
	public byte[] getSecret() {
		return secret;
	}
	public void setSecret(byte[] secret) {
		this.secret = secret;
	}
	public String getCode() {
		return code;
	}
	public void setCode(String code) {
		this.code = code;
	}
}
