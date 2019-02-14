package com.fortunato.twoFactorAuth.constant;

public enum MessagesConstants {

	VERIFY_KEY("Verificando key"),
	EMPTY_KEY("Parametro necessario se encontra vazio"),
	ERROR_KEY("Erro ao gerar key"),
	
	VERIFY_CODE("Verificando code"),
	EMPTY_CODE("Parametro necessario se encontra vazio"),
	ERROR_CODE("Codigo nao e valido");

	private final String description;

	private MessagesConstants(String description) {
		this.description = description;
	}

	public String getDescription() {
		return description;
	}

}
