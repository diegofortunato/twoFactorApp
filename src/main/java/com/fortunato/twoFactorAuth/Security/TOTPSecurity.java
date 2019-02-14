package com.fortunato.twoFactorAuth.Security;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * 
 * Classe responsavel por todo o algoritmo TOTP: Time-Based One-Time Password Algorithm
 * 
 * 
 */
public class TOTPSecurity {

	private static final int[] DIGITS_POWER
	// 0 1 2 3 4 5 6 7 8
			= { 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000 };

	/**
	 * Algoritmo padrão (Compativel com o Google Authenticator)
	 */
	public static final String DEFAULT_ALGORITHM = "HmacSHA1";

	/**
	 * Intervalo de tempo padrão em segundos (Compativel com o Google Authenticator)
	 */
	public static final int DEFAULT_INTERVAL = 30;

	/**
	 * Etapas padrão do intervalo de tempo para verificar a validade
	 */
	public static final int DEFAULT_STEPS = 1;

	/**
	 * Tamanho padrão do codigo (Compativel com o Google Authenticator)
	 */
	public static final int DEFAULT_LENGTH = 6;

	/**
	 * Hora padrão 0 para o intervalo
	 */
	public static final int DEFAULT_T0 = 0;

	private final String algorithm;

	private final int interval;

	private final int length;

	private final int steps;

	private final int t0;

	/**
	 * Criar uma instância padrão do TOTP compatível com o Google Authenticator
	 */
	public TOTPSecurity() {
		this(DEFAULT_ALGORITHM, DEFAULT_INTERVAL, DEFAULT_LENGTH, DEFAULT_STEPS, DEFAULT_T0);
	}

	/**
	 * @param   HmacSHA1, HmacSHA256, HmacSHA512
	 * @param o intervalo de tempo em segundos para usar
	 */
	public TOTPSecurity(String algorithm, int interval) {
		this(algorithm, interval, DEFAULT_LENGTH, DEFAULT_STEPS, DEFAULT_T0);
	}

	/**
	 * Criar nova instância TOTP com intervalo de tempo próprio
	 * 
	 * @param Intervalo de tempo para uso
	 */
	public TOTPSecurity(int interval) {
		this(DEFAULT_ALGORITHM, interval, DEFAULT_LENGTH, DEFAULT_STEPS, DEFAULT_T0);
	}

	/**
	 * @param Intervalo em segundos para o uso
	 * @param Tamanho   do codigo para uso; deve estar entre 1 e 8
	 * @param Passos    do histórico para validar o código
	 */
	public TOTPSecurity(int interval, int length, int steps) {
		this(DEFAULT_ALGORITHM, interval, length, steps, DEFAULT_T0);
	}

	/**
	 * Criar nova instância TOTP com configuração própria
	 * 
	 * @param Algoritmo para uso; disponiveis HmacSHA1, HmacSHA256, HmacSHA512
	 * @param Intervalo em segundos para o uso
	 * @param Tamanho   do codigo para uso; deve estar entre 1 e 8
	 * @param Passos    do histórico para validar o código
	 * @param Tempo     0 a ser usado para intervalo
	 */
	public TOTPSecurity(String algorithm, int interval, int length, int steps, int t0) {
		this.algorithm = algorithm;
		this.interval = Math.abs(interval);
		this.length = Math.abs(length);
		this.steps = Math.abs(steps);
		this.t0 = Math.abs(t0);

		if (length > DIGITS_POWER.length || length < 1) {
			throw new IllegalArgumentException("Length must be between 1 and 8");
		}
	}

	/**
	 * @return o algoritmo sendo usado
	 */
	public String getAlgorithm() {
		return algorithm;
	}

	/**
	 * @return o intervalo sendo usado
	 */
	public int getInterval() {
		return interval;
	}

	/**
	 * @return o tamanho sendo usado
	 */
	public int getLength() {
		return length;
	}

	/**
	 * @return os passos sendo usado
	 */
	public int getSteps() {
		return steps;
	}

	/**
	 * @return o tempo 0 a ser usado para o intervalo
	 */
	public int getT0() {
		return t0;
	}

	/**
	 * Gera o código TOTP para o intervalo de tempo atual
	 * 
	 * @param secret usada
	 * @return codigo gerado
	 */
	public final String generate(byte[] secret) {
		return generateOTP(secret, getCurrentTimeInterval());
	}

	/**
	 * Gera o código TOTP para determinado tempo
	 * 
	 * @param secret para uso
	 * @param tempo  em milissegundos para gerar código
	 * @return codigo gerado
	 */
	public final String generate(byte[] secret, long time) {
		return generateOTP(secret, getTimeInterval(time));
	}

	/**
	 * Valida o código TOTP para o intervalo de tempo atual
	 * 
	 * @param secret para uso
	 * @param codigo para validar
	 * @return verdadeiro se o codigo for valido
	 */
	public final boolean validate(byte[] secret, String code) {
		return validate(secret, code, System.currentTimeMillis());
	}

	/**
	 * Valida o código TOTP para o intervalo de tempo atual
	 * 
	 * @param secret para uso
	 * @param codigo para validar
	 * @param tempo  em milissegundos para validar o código novamente
	 * @return verdadeiro se o codigo for valido
	 */
	public final boolean validate(byte[] secret, String code, long time) {
		int steps = getSteps();
		long itvl = getTimeInterval(time);

		for (int i = 0; i <= steps; i++) {
			boolean result = validateOTP(secret, itvl - i, code);
			if (result) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Gera o código TOTP para dar intervalo de tempo
	 * 
	 * @param secret para uso
	 * @param itvl   o intervalo de tempo para usar
	 * @return codigo gerado
	 */
	final String generateOTP(byte[] secret, long itvl) {
		byte[] text = ByteBuffer.allocate(8).putLong(itvl).array();
		byte[] hash = getShaHash(secret, text);

		int off = hash[hash.length - 1] & 0xf;
		int bin = ((hash[off] & 0x7f) << 24) | ((hash[off + 1] & 0xff) << 16) | ((hash[off + 2] & 0xff) << 8)
				| (hash[off + 3] & 0xff);

		int otp = bin % DIGITS_POWER[getLength()];
		String result = Integer.toString(otp);
		while (result.length() < getLength()) {
			result = "0" + result;
		}
		return result;
	}

	final boolean validateOTP(byte[] secret, long itvl, String code) {
		String hash = generateOTP(secret, itvl);
		return hash.equals(code);
	}

	private byte[] getShaHash(byte[] key, byte[] text) {
		try {
			Mac mac = Mac.getInstance(getAlgorithm());
			SecretKeySpec spec = new SecretKeySpec(key, "RAW");
			mac.init(spec);
			return mac.doFinal(text);
		} catch (GeneralSecurityException e) {
			throw new IllegalStateException(e);
		}
	}

	long getTimeInterval(long time) {
		return ((time / 1000) - getT0()) / getInterval();
	}

	long getCurrentTimeInterval() {
		return getTimeInterval(System.currentTimeMillis());
	}
}
