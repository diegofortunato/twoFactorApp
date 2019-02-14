package com.fortunato.twoFactorAuth.util;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;

import org.apache.commons.codec.binary.Base32;

/**
 * Classe responsavel por gerar e manipular secrets necessarias
 * 
 */
public class SecretUtil {

	private static final Random rand = new Random();

	public enum Size {
		DEFAULT(20), MEDIUM(32), LARGE(64);

		private int size;

		Size(int size) {
			this.size = size;
		}

		public int getSize() {
			return size;
		}
	}

	/**
	 * Gera uma secret aleatoria com o tamanho de 20 bytes
	 * 
	 * @return secret gerada
	 */
	public static final byte[] generate() {
		return generate(Size.DEFAULT);
	}

	/**
	 * Gera bytes aleatorios de um tamanho determinado que Ã© passado por parametro
	 * 
	 * @return secret gerada
	 */
	public static final byte[] generate(Size size) {
		byte[] b = new byte[size.getSize()];
		rand.nextBytes(b);
		return Arrays.copyOf(b, size.getSize());
	}

	/**
	 * Codifica a secret para Base32
	 * 
	 * @param secret usada
	 * @return secret codificaada para Base32
	 */
	public static final String toBase32(byte[] secret) {
		return new String(new Base32().encode(secret));
	}

	/**
	 * Decodifica secret que esta em Base32 para bytes
	 * 
	 * @param base32 usada
	 * @return secret decodificada
	 */
	public static final byte[] fromBase32(String base32) {
		return new Base32().decode(base32);
	}

	public static final String toHex(byte[] secret) {
		return String.format("%x", new BigInteger(1, secret));
	}

	public static final byte[] fromHex(String hex) {
		// Adding one byte to get the right conversion
		// Values starting with "0" can be converted
		byte[] bArray = new BigInteger("10" + hex, 16).toByteArray();

		// Copy all the REAL bytes, not the "first"
		byte[] ret = new byte[bArray.length - 1];
		for (int i = 0; i < ret.length; i++)
			ret[i] = bArray[i + 1];
		return ret;
	}

}