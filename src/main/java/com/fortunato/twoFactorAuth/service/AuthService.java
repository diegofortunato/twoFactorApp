package com.fortunato.twoFactorAuth.service;

import javax.validation.Valid;

import com.fortunato.twoFactorAuth.model.AuthModel;

public interface AuthService {

	AuthModel generateKey(@Valid String key);
	Boolean verifySecret(@Valid byte[] secret, @Valid String code);

}
