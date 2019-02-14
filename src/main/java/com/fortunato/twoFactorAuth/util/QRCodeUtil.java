package com.fortunato.twoFactorAuth.util;

/**
 * Classe utilizada para o Google Authenticator, gera e retorna QR Code para leitura do APP
 */
public class QRCodeUtil {
	
	/**
	 * Retorna QR Code que pode ser aberto no navegador e verificado pelo aplicativo
	 * 
	 * @param Key
	 * @param Host
	 * @param Secret
	 * @return QR Code
	 */
	public static final String getQRCode(String username, String host, String secret) {
		String format = "https://chart.googleapis.com/chart?chs=200x200&chld=M%%7C0&cht=qr&chl=otpauth://totp/%s@%s?secret=%s";
		return String.format(format, username, host, secret);
	}
}
