/**
 *  Created on  : 14/04/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	
 */
package cinvestav.android.pki.cryptography.utils;

import java.io.UnsupportedEncodingException;
import java.security.KeyStore;
import java.security.Security;

import javax.crypto.SecretKey;

import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.util.encoders.Base64;
import org.spongycastle.util.encoders.Hex;

import cinvestav.android.pki.cryptography.algorithm.AES;
import cinvestav.android.pki.cryptography.exception.CryptoUtilsException;

/**
 * @author Ing. Javier Silva Pérez - [javier]
 * 
 */
public class SymmetricCryptoUtils implements
		ISymmetricCryptoUtils {
	
	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.cryptography.android.utils.ISymmetricCryptoUtils#encryptAES
	 * (java.lang.String, byte[])
	 */
	@Override
	public String aes_encrypt(String plainText, byte[] key)
			throws CryptoUtilsException {
		AES aes = new AES(128);

		try {
			return new String(Base64.encode(aes.encrypt(
					plainText.getBytes("UTF-8"), key)));
		} catch (UnsupportedEncodingException e) {

			throw new CryptoUtilsException(e.getMessage(), e);
		}

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.cryptography.android.utils.ISymmetricCryptoUtils#encryptAES
	 * (java.lang.Integer, java.lang.String, byte[])
	 */
	@Override
	public String aes_encrypt(Integer keySize, String plainText, byte[] key)
			throws CryptoUtilsException {

		AES aes = new AES(keySize);

		try {
			return new String(Base64.encode(aes.encrypt(
					plainText.getBytes("UTF-8"), key)));
		} catch (UnsupportedEncodingException e) {

			throw new CryptoUtilsException(e.getMessage(), e);
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.cryptography.android.utils.ISymmetricCryptoUtils#encryptAES
	 * (java.lang.Integer, java.lang.String, java.lang.String, byte[])
	 */
	@Override
	public String aes_encrypt(Integer keySize, String coder, String plainText,
			byte[] key) throws CryptoUtilsException {

		AES aes = new AES(keySize);

		try {
			if (coder.equalsIgnoreCase(CryptoUtils.ENCODER_BASE64)) {
				return new String(Base64.encode(aes.encrypt(
						plainText.getBytes("UTF-8"), key)));
			}
			if (coder.equalsIgnoreCase(CryptoUtils.ENCODER_HEX)) {
				return new String(Hex.encode(aes.encrypt(
						plainText.getBytes("UTF-8"), key)));
			}

			throw new CryptoUtilsException(
					"Encryption error: Unsupported encoder [" + coder + "]");
		} catch (UnsupportedEncodingException e) {

			throw new CryptoUtilsException(e.getMessage(), e);
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.cryptography.android.utils.ISymmetricCryptoUtils#encryptAES
	 * (java.lang.Integer, java.lang.String, java.lang.String, byte[], byte[])
	 */
	@Override
	public String aes_encrypt(Integer keySize, String coder, String plainText,
			byte[] key, byte[] iv) throws CryptoUtilsException {

		AES aes = new AES(keySize);
		try {
			if (coder.equalsIgnoreCase(CryptoUtils.ENCODER_BASE64)) {
				return new String(Base64.encode(aes.encrypt(
						plainText.getBytes("UTF-8"), key, iv)));
			}
			if (coder.equalsIgnoreCase(CryptoUtils.ENCODER_HEX)) {
				return new String(Hex.encode(aes.encrypt(
						plainText.getBytes("UTF-8"), key, iv)));
			}

			throw new CryptoUtilsException(
					"Encryption error: Unsupported encoder [" + coder + "]");
		} catch (UnsupportedEncodingException e) {

			throw new CryptoUtilsException(e.getMessage(), e);
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.cryptography.android.utils.ISymmetricCryptoUtils#encryptAES
	 * (java.lang.Integer, java.lang.String, java.lang.String, byte[], byte[],
	 * java.lang.String)
	 */
	@Override
	public String aes_encrypt(Integer keySize, String coder, String plainText,
			byte[] key, byte[] iv, String operationMode)
			throws CryptoUtilsException {

		AES aes = new AES(keySize);
		try {
			if (coder.equalsIgnoreCase(CryptoUtils.ENCODER_BASE64)) {
				return new String(Base64.encode(aes.encrypt(
						plainText.getBytes("UTF-8"), key, iv, operationMode)));
			}
			if (coder.equalsIgnoreCase(CryptoUtils.ENCODER_HEX)) {
				return new String(Hex.encode(aes.encrypt(
						plainText.getBytes("UTF-8"), key, iv, operationMode)));
			}

			throw new CryptoUtilsException(
					"Encryption error: Unsupported encoder [" + coder + "]");
		} catch (UnsupportedEncodingException e) {

			throw new CryptoUtilsException(e.getMessage(), e);
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.cryptography.android.utils.ISymmetricCryptoUtils#encryptAES
	 * (java.lang.Integer, java.lang.String, java.lang.String, byte[], byte[],
	 * java.lang.String, java.lang.String)
	 */
	@Override
	public String aes_encrypt(Integer keySize, String coder, String plainText,
			byte[] key, byte[] iv, String operationMode, String paddingStyle)
			throws CryptoUtilsException {

		AES aes = new AES(keySize);
		try {
			if (coder.equalsIgnoreCase(CryptoUtils.ENCODER_BASE64)) {
				return new String(Base64.encode(aes.encrypt(
						plainText.getBytes("UTF-8"), key, iv, operationMode,
						paddingStyle)));
			}
			if (coder.equalsIgnoreCase(CryptoUtils.ENCODER_HEX)) {
				return new String(Hex.encode(aes.encrypt(
						plainText.getBytes("UTF-8"), key, iv, operationMode,
						paddingStyle)));
			}

			throw new CryptoUtilsException(
					"Encryption error: Unsupported encoder [" + coder + "]");
		} catch (UnsupportedEncodingException e) {

			throw new CryptoUtilsException(e.getMessage(), e);
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.cryptography.android.utils.ISymmetricCryptoUtils#encryptAES
	 * (byte[], byte[])
	 */
	@Override
	public byte[] aes_encrypt(byte[] plainText, byte[] key)
			throws CryptoUtilsException {

		AES aes = new AES(128);
		return aes.encrypt(plainText, key);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.cryptography.android.utils.ISymmetricCryptoUtils#encryptAES
	 * (java.lang.Integer, byte[], byte[])
	 */
	@Override
	public byte[] aes_encrypt(Integer keySize, byte[] plainText, byte[] key)
			throws CryptoUtilsException {

		AES aes = new AES(keySize);
		return aes.encrypt(plainText, key);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.cryptography.android.utils.ISymmetricCryptoUtils#encryptAES
	 * (java.lang.Integer, byte[], byte[], byte[])
	 */
	@Override
	public byte[] aes_encrypt(Integer keySize, byte[] plainText, byte[] key,
			byte[] iv) throws CryptoUtilsException {

		AES aes = new AES(keySize);
		return aes.encrypt(plainText, key, iv);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.cryptography.android.utils.ISymmetricCryptoUtils#encryptAES
	 * (java.lang.Integer, byte[], byte[], byte[], java.lang.String)
	 */
	@Override
	public byte[] aes_encrypt(Integer keySize, byte[] plainText, byte[] key,
			byte[] iv, String operationMode) throws CryptoUtilsException {

		AES aes = new AES(keySize);
		return aes.encrypt(plainText, key, iv, operationMode);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.cryptography.android.utils.ISymmetricCryptoUtils#encryptAES
	 * (java.lang.Integer, byte[], byte[], byte[], java.lang.String,
	 * java.lang.String)
	 */
	@Override
	public byte[] aes_encrypt(Integer keySize, byte[] plainText, byte[] key,
			byte[] iv, String operationMode, String paddingStyle)
			throws CryptoUtilsException {

		AES aes = new AES(keySize);
		return aes.encrypt(plainText, key, iv, operationMode, paddingStyle);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.cryptography.android.utils.ISymmetricCryptoUtils#decryptAES
	 * (java.lang.String, byte[])
	 */
	@Override
	public String aes_decrypt(String cypherText, byte[] key)
			throws CryptoUtilsException {

		AES aes = new AES(128);
		return new String(aes.decrypt(Base64.decode(cypherText), key));
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.cryptography.android.utils.ISymmetricCryptoUtils#decryptAES
	 * (java.lang.Integer, java.lang.String, byte[])
	 */
	@Override
	public String aes_decrypt(Integer keySize, String cypherText, byte[] key)
			throws CryptoUtilsException {

		AES aes = new AES(keySize);
		return new String(aes.decrypt(Base64.decode(cypherText), key));
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.cryptography.android.utils.ISymmetricCryptoUtils#decryptAES
	 * (java.lang.Integer, java.lang.String, java.lang.String, byte[])
	 */
	@Override
	public String aes_decrypt(Integer keySize, String coder, String cypherText,
			byte[] key) throws CryptoUtilsException {

		AES aes = new AES(keySize);
		if (coder.equalsIgnoreCase(CryptoUtils.ENCODER_BASE64)) {
			return new String(aes.decrypt(Base64.decode(cypherText), key));
		}
		if (coder.equalsIgnoreCase(CryptoUtils.ENCODER_HEX)) {
			return new String(aes.decrypt(Hex.decode(cypherText), key));
		}

		throw new CryptoUtilsException(
				"Encryption error: Unsupported encoder [" + coder + "]");
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.cryptography.android.utils.ISymmetricCryptoUtils#decryptAES
	 * (java.lang.Integer, java.lang.String, java.lang.String, byte[], byte[])
	 */
	@Override
	public String aes_decrypt(Integer keySize, String coder, String cypherText,
			byte[] key, byte[] iv) throws CryptoUtilsException {

		AES aes = new AES(keySize);
		if (coder.equalsIgnoreCase(CryptoUtils.ENCODER_BASE64)) {
			return new String(aes.decrypt(Base64.decode(cypherText), key, iv));
		}
		if (coder.equalsIgnoreCase(CryptoUtils.ENCODER_HEX)) {
			return new String(aes.decrypt(Hex.decode(cypherText), key, iv));
		}

		throw new CryptoUtilsException(
				"Encryption error: Unsupported encoder [" + coder + "]");
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.cryptography.android.utils.ISymmetricCryptoUtils#decryptAES
	 * (java.lang.Integer, java.lang.String, java.lang.String, byte[], byte[],
	 * java.lang.String)
	 */
	@Override
	public String aes_decrypt(Integer keySize, String coder, String cypherText,
			byte[] key, byte[] iv, String operationMode)
			throws CryptoUtilsException {

		AES aes = new AES(keySize);
		if (coder.equalsIgnoreCase(CryptoUtils.ENCODER_BASE64)) {
			return new String(aes.decrypt(Base64.decode(cypherText), key, iv,
					operationMode));
		}
		if (coder.equalsIgnoreCase(CryptoUtils.ENCODER_HEX)) {
			return new String(aes.decrypt(Hex.decode(cypherText), key, iv,
					operationMode));
		}

		throw new CryptoUtilsException(
				"Encryption error: Unsupported encoder [" + coder + "]");
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.cryptography.android.utils.ISymmetricCryptoUtils#decryptAES
	 * (java.lang.Integer, java.lang.String, java.lang.String, byte[], byte[],
	 * java.lang.String, java.lang.String)
	 */
	@Override
	public String aes_decrypt(Integer keySize, String coder, String cypherText,
			byte[] key, byte[] iv, String operationMode, String paddingStyle)
			throws CryptoUtilsException {

		AES aes = new AES(keySize);
		if (coder.equalsIgnoreCase(CryptoUtils.ENCODER_BASE64)) {
			return new String(aes.decrypt(Base64.decode(cypherText), key, iv,
					operationMode, paddingStyle));
		}
		if (coder.equalsIgnoreCase(CryptoUtils.ENCODER_HEX)) {
			return new String(aes.decrypt(Hex.decode(cypherText), key, iv,
					operationMode, paddingStyle));
		}

		throw new CryptoUtilsException(
				"Encryption error: Unsupported encoder [" + coder + "]");
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.cryptography.android.utils.ISymmetricCryptoUtils#decryptAES
	 * (byte[], byte[])
	 */
	@Override
	public byte[] aes_decrypt(byte[] cypherText, byte[] key)
			throws CryptoUtilsException {

		AES aes = new AES(128);
		return aes.decrypt(cypherText, key);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.cryptography.android.utils.ISymmetricCryptoUtils#decryptAES
	 * (java.lang.Integer, byte[], byte[])
	 */
	@Override
	public byte[] aes_decrypt(Integer keySize, byte[] cypherText, byte[] key)
			throws CryptoUtilsException {

		AES aes = new AES(keySize);
		return aes.decrypt(cypherText, key);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.cryptography.android.utils.ISymmetricCryptoUtils#decryptAES
	 * (java.lang.Integer, byte[], byte[], byte[])
	 */
	@Override
	public byte[] aes_decrypt(Integer keySize, byte[] cypherText, byte[] key,
			byte[] iv) throws CryptoUtilsException {

		AES aes = new AES(keySize);
		return aes.decrypt(cypherText, key, iv);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.cryptography.android.utils.ISymmetricCryptoUtils#decryptAES
	 * (java.lang.Integer, byte[], byte[], byte[], java.lang.String)
	 */
	@Override
	public byte[] aes_decrypt(Integer keySize, byte[] cypherText, byte[] key,
			byte[] iv, String operationMode) throws CryptoUtilsException {

		AES aes = new AES(keySize);
		return aes.decrypt(cypherText, key, iv, operationMode);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.cryptography.android.utils.ISymmetricCryptoUtils#decryptAES
	 * (java.lang.Integer, byte[], byte[], byte[], java.lang.String,
	 * java.lang.String)
	 */
	@Override
	public byte[] aes_decrypt(Integer keySize, byte[] cypherText, byte[] key,
			byte[] iv, String operationMode, String paddingStyle)
			throws CryptoUtilsException {

		AES aes = new AES(keySize);
		return aes.decrypt(cypherText, key, iv, operationMode, paddingStyle);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see cinvestav.cryptography.android.utils.ISymmetricCryptoUtils#
	 * generateAESKey(java.lang.Integer)
	 */
	@Override
	public byte[] aes_generateKey(Integer keySize)
			throws CryptoUtilsException {

		AES aes = new AES(keySize);
		return aes.createParametersKey().getKey();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.cryptography.android.utils.ISymmetricCryptoUtils#getAESKey
	 * (java.lang.String)
	 */
	@Override
	public byte[] aes_getKey(String keyFileName)
			throws CryptoUtilsException {

		AES aes = new AES();
		return aes.getKey(keyFileName);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.cryptography.android.utils.ISymmetricCryptoUtils#getAESKey
	 * (java.security.KeyStore, java.lang.String, java.lang.String)
	 */
	@Override
	public byte[] aes_getKey(KeyStore ks, String keyAlias, String keyPassword)
			throws CryptoUtilsException {

		AES aes = new AES();
		return aes.getKey(ks, keyAlias, keyPassword);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see cinvestav.cryptography.android.utils.ISymmetricCryptoUtils#
	 * addAESKeyToKeyStore(java.security.KeyStore, javax.crypto.SecretKey,
	 * java.lang.String, java.lang.String)
	 */
	@Override
	public void aes_addKeyToKeyStore(KeyStore ks, SecretKey key, String alias,
			String keyPassword) throws CryptoUtilsException {
		AES aes = new AES();
		aes.addKeyToKeyStore(ks, key, alias, keyPassword);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see cinvestav.cryptography.android.utils.ISymmetricCryptoUtils#
	 * saveAESKeyToFile(byte[], java.lang.String)
	 */
	@Override
	public void aes_saveKeyToFile(byte[] key, String fileFullName)
			throws CryptoUtilsException {
		AES aes = new AES();
		aes.saveKeyToFile(key, fileFullName);
	}

	@Override
	public SecretKey aes_getSecretKey(byte[] key)
			throws CryptoUtilsException {
		// TODO Auto-generated method stub
		AES aes = new AES();
		return aes.createSecretKey(key);
	}

}
