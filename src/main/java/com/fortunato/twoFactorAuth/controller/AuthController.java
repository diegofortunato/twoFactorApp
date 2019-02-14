package com.fortunato.twoFactorAuth.controller;

import javax.validation.Valid;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.fortunato.twoFactorAuth.constant.MessagesConstants;
import com.fortunato.twoFactorAuth.exception.ApplicationException;
import com.fortunato.twoFactorAuth.model.AuthModel;
import com.fortunato.twoFactorAuth.model.RequestModel;
import com.fortunato.twoFactorAuth.response.Response;
import com.fortunato.twoFactorAuth.service.AuthService;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "*")
public class AuthController {

	private static final Logger log = LoggerFactory.getLogger(AuthController.class);

	@Autowired
	private AuthService authService;

	/**
	 * Recebe uma chave e gera uma key baseada no protocolo do Google.
	 * 
	 * @param key
	 * @param result
	 * @return ResponseEntity<Response<AuthModel>>
	 * @throws ApplicationException
	 */
	@PostMapping(value = "/generate")
	public ResponseEntity<Response<AuthModel>> generateKey(@Valid @RequestBody String key, BindingResult result)
			throws ApplicationException {
		Response<AuthModel> response = new Response<AuthModel>();
		log.info(MessagesConstants.VERIFY_KEY.getDescription(), key);
		if (key == null || key.isEmpty()) {
			log.error(MessagesConstants.EMPTY_KEY.getDescription(), result.getAllErrors());
			result.getAllErrors().forEach(error -> response.getErrors().add(error.getDefaultMessage()));
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
		}
		AuthModel generatedModel = this.authService.generateKey(key);
		if (generatedModel != null) {
			response.setData(generatedModel);
			return ResponseEntity.ok(response);
		} else {
			log.info(MessagesConstants.ERROR_KEY.getDescription(), key);
			response.getErrors().add(MessagesConstants.ERROR_KEY.getDescription() + key);
			return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
		}
	}
	
	
	/**
	 * Recebe uma chave e o codigo e verifica autenticidade.
	 * 
	 * @param secret
	 * @param code
	 * @param result
	 * @return ResponseEntity<Response<Boolean>>
	 * @throws ApplicationException
	 */
	@PostMapping(value = "/verify")
	public ResponseEntity<Response<Boolean>> verifyValidation(@Valid @RequestBody RequestModel request, BindingResult result)
			throws ApplicationException {
		Response<Boolean> response = new Response<Boolean>();
		log.info(MessagesConstants.VERIFY_KEY.getDescription(), request.getSecret());
		log.info(MessagesConstants.VERIFY_CODE.getDescription(), request.getCode());
		if (request.getSecret() == null) {
			log.error(MessagesConstants.EMPTY_KEY.getDescription(), result.getAllErrors());
			result.getAllErrors().forEach(error -> response.getErrors().add(error.getDefaultMessage()));
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
		}
		if (request.getCode() == null || request.getCode().isEmpty()) {
			log.error(MessagesConstants.EMPTY_CODE.getDescription(), result.getAllErrors());
			result.getAllErrors().forEach(error -> response.getErrors().add(error.getDefaultMessage()));
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
		}
		Boolean valid = this.authService.verifySecret(request.getSecret(), request.getCode());
		response.setData(valid);
		if (valid) {
			return ResponseEntity.ok(response);
		} else {
			log.info(MessagesConstants.ERROR_CODE.getDescription());
			response.getErrors().add(MessagesConstants.ERROR_CODE.getDescription());
			return ResponseEntity.ok(response);
		}
	}
}
