package com.fortunato.twoFactorAuth.service.impl;

import javax.validation.Valid;

import org.springframework.stereotype.Service;

import com.fortunato.twoFactorAuth.Security.TOTPSecurity;
import com.fortunato.twoFactorAuth.model.AuthModel;
import com.fortunato.twoFactorAuth.service.AuthService;
import com.fortunato.twoFactorAuth.util.QRCodeUtil;
import com.fortunato.twoFactorAuth.util.SecretUtil;

@Service
public class AuthServiceImpl implements AuthService{

	
	@Override
	public AuthModel generateKey(@Valid String key) {

		AuthModel model = new AuthModel();
		
		byte[] secret = SecretUtil.generate();
		
		String encoded = SecretUtil.toBase32(secret);
		String qr = QRCodeUtil.getQRCode(key, "teste.com", encoded);
		
		model.setQrCode(qr);
		model.setKey(key);
		model.setSecret(secret);
		model.setEncoded(encoded);
		
		return model;
	}

	@Override
	public Boolean verifySecret(@Valid byte[] secret, @Valid String code) {
		Boolean result = false;
		TOTPSecurity manager = new TOTPSecurity();
		result = manager.validate(secret, code);	
		return result;
	}
}
