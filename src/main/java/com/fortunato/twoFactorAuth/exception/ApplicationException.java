package com.fortunato.twoFactorAuth.exception;

public class ApplicationException extends Exception {
	private static final long serialVersionUID = 5001497032149874783L;

	public ApplicationException(){
		super();
	}
	
	public ApplicationException(String message){
		super(message);
	}
}