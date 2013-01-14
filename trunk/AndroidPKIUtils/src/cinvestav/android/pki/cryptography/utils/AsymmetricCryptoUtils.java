/**
 *  Created on  : 15/04/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	
 */
package cinvestav.android.pki.cryptography.utils;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.Security;
import java.util.LinkedList;
import java.util.List;

import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.util.encoders.Base64;
import org.spongycastle.util.encoders.Hex;

import cinvestav.android.pki.cryptography.algorithm.EC;
import cinvestav.android.pki.cryptography.algorithm.RSA;
import cinvestav.android.pki.cryptography.ec.ECDomainParameters;
import cinvestav.android.pki.cryptography.exception.CryptoUtilsException;
import cinvestav.android.pki.cryptography.key.ECKeyPair;
import cinvestav.android.pki.cryptography.key.ECPrivateKey;
import cinvestav.android.pki.cryptography.key.ECPublicKey;
import cinvestav.android.pki.cryptography.key.RSAKeyPair;
import cinvestav.android.pki.cryptography.key.RSAPrivateKey;
import cinvestav.android.pki.cryptography.key.RSAPublicKey;

/**
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 11/06/2012
 * @version 1.0
 */
public class AsymmetricCryptoUtils implements
		IAsymmetricCryptoUtils {
	
	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	RSA rsa;
	EC ec;
	SymmetricCryptoUtils androidSymmetricCryptoUtils;

	/**
	 * @throws CryptoUtilsException
	 * 
	 */
	public AsymmetricCryptoUtils(){
		// TODO Auto-generated constructor stub
		rsa = new RSA();
		ec = new EC();
		androidSymmetricCryptoUtils = new SymmetricCryptoUtils();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see cinvestav.cryptography.android.utils.IAsymmetricCryptoUtils#
	 * encrypt(byte[], org.spongycastle.crypto.params.RSAKeyParameters,
	 * java.lang.String)
	 */
	@Override
	public List<byte[]> encrypt(byte[] plainText, RSAPublicKey publicKey,
			String operationMode) throws CryptoUtilsException {

		// Create a random 256 bits sessionKey
		
		byte[] sessionKey = androidSymmetricCryptoUtils.aes_generateKey(256);

		// Encrypt session key using EC IES
		byte[] encSessionKey = rsa
				.encrypt(sessionKey, publicKey, operationMode);

		// Create return list and fill it
		List<byte[]> res = new LinkedList<byte[]>();
		// Use the encrypted session key to encrypt the original input
		res.add(androidSymmetricCryptoUtils.aes_encrypt(256, plainText, sessionKey));
		res.add(encSessionKey);
		return res;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see cinvestav.cryptography.android.utils.IAsymmetricCryptoUtils#
	 * encrypt(byte[], org.spongycastle.crypto.params.RSAKeyParameters)
	 */
	@Override
	public List<byte[]> encrypt(byte[] plainText, RSAPublicKey publicKey)
			throws CryptoUtilsException {

		// Create a random 256 bits sessionKey
		byte[] sessionKey = androidSymmetricCryptoUtils.aes_generateKey(256);

		// Encrypt session key using EC IES
		byte[] encSessionKey = rsa.encrypt(sessionKey, publicKey,
				RSA.OPERATION_MODE_PKCS1);

		// Create return list and fill it
		List<byte[]> res = new LinkedList<byte[]>();
		// Use the encrypted session key to encrypt the original input
		res.add(androidSymmetricCryptoUtils.aes_encrypt(256, plainText, sessionKey));
		res.add(encSessionKey);
		return res;

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see cinvestav.cryptography.android.utils.IAsymmetricCryptoUtils#
	 * encrypt(java.lang.String,
	 * org.spongycastle.crypto.params.RSAKeyParameters, java.lang.String,
	 * java.lang.String)
	 */
	@Override
	public List<String> encrypt(String plainText, RSAPublicKey publicKey,
			String encoder, String operationMode)
			throws CryptoUtilsException {

		try {
			byte[] sessionKey;
			byte[] encSessionKey;
			List<String> res;
			if (encoder.equalsIgnoreCase(CryptoUtils.ENCODER_BASE64)) {
				// Create a random 256 bits sessionKey
				sessionKey = androidSymmetricCryptoUtils.aes_generateKey(256);
				

				// Encrypt session key using EC IES
				encSessionKey = rsa.encrypt(sessionKey, publicKey,
						operationMode);

				// Create return list and fill it
				res = new LinkedList<String>();
				// Use the encrypted session key to encrypt the original input
				res.add(new String(Base64.encode(androidSymmetricCryptoUtils.aes_encrypt(256,
						plainText.getBytes("UTF-8"), sessionKey))));
				res.add(new String(Base64.encode(encSessionKey)));
				return res;
			}
			if (encoder.equalsIgnoreCase(CryptoUtils.ENCODER_HEX)) {
				sessionKey = androidSymmetricCryptoUtils.aes_generateKey(256);
				

				// Encrypt session key using EC IES
				encSessionKey = rsa.encrypt(sessionKey, publicKey,
						operationMode);

				// Create return list and fill it
				res = new LinkedList<String>();
				// Use the encrypted session key to encrypt the original input
				res.add(new String(Hex.encode(androidSymmetricCryptoUtils.aes_encrypt(256,
						plainText.getBytes("UTF-8"), sessionKey))));
				res.add(new String(Hex.encode(encSessionKey)));
				return res;
			}

			throw new CryptoUtilsException(
					"Encryption error: Unsupported encoder [" + encoder + "]");
		} catch (UnsupportedEncodingException e) {

			throw new CryptoUtilsException("RSA Encryption error: " + e,
					e);
		}

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see cinvestav.cryptography.android.utils.IAsymmetricCryptoUtils#
	 * encrypt(java.lang.String,
	 * org.spongycastle.crypto.params.RSAKeyParameters, java.lang.String)
	 */
	@Override
	public List<String> encrypt(String plainText, RSAPublicKey publicKey,
			String encoder) throws CryptoUtilsException {

		try {
			byte[] sessionKey;
			byte[] encSessionKey;
			List<String> res;
			if (encoder.equalsIgnoreCase(CryptoUtils.ENCODER_BASE64)) {
				// Create a random 256 bits sessionKey
				sessionKey = androidSymmetricCryptoUtils.aes_generateKey(256);
				

				// Encrypt session key using EC IES
				encSessionKey = rsa.encrypt(sessionKey, publicKey,
						RSA.OPERATION_MODE_PKCS1);

				// Create return list and fill it
				res = new LinkedList<String>();
				// Use the encrypted session key to encrypt the original input
				res.add(new String(Base64.encode(androidSymmetricCryptoUtils.aes_encrypt(256,
						plainText.getBytes("UTF-8"), sessionKey))));
				res.add(new String(Base64.encode(encSessionKey)));
				return res;
			}
			if (encoder.equalsIgnoreCase(CryptoUtils.ENCODER_HEX)) {
				sessionKey = androidSymmetricCryptoUtils.aes_generateKey(256);
				

				// Encrypt session key using EC IES
				encSessionKey = rsa.encrypt(sessionKey, publicKey,
						RSA.OPERATION_MODE_PKCS1);

				// Create return list and fill it
				res = new LinkedList<String>();
				// Use the encrypted session key to encrypt the original input
				res.add(new String(Hex.encode(androidSymmetricCryptoUtils.aes_encrypt(256,
						plainText.getBytes("UTF-8"), sessionKey))));
				res.add(new String(Hex.encode(encSessionKey)));
				return res;
			}

			throw new CryptoUtilsException(
					"Encryption error: Unsupported encoder [" + encoder + "]");
		} catch (UnsupportedEncodingException e) {

			throw new CryptoUtilsException("RSA Encryption error: " + e,
					e);
		}

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see cinvestav.cryptography.android.utils.IAsymmetricCryptoUtils#
	 * encrypt(java.lang.String,
	 * org.spongycastle.crypto.params.RSAKeyParameters)
	 */
	@Override
	public List<String> encrypt(String plainText, RSAPublicKey publicKey)
			throws CryptoUtilsException {
		try {
			byte[] sessionKey;
			byte[] encSessionKey;
			List<String> res;
			// Create a random 256 bits sessionKey
			sessionKey = androidSymmetricCryptoUtils.aes_generateKey(256);
			

			// Encrypt session key using EC IES
			encSessionKey = rsa.encrypt(sessionKey, publicKey,
					RSA.OPERATION_MODE_PKCS1);

			// Create return list and fill it
			res = new LinkedList<String>();
			// Use the encrypted session key to encrypt the original input
			res.add(new String(Base64.encode(androidSymmetricCryptoUtils.aes_encrypt(256,
					plainText.getBytes("UTF-8"), sessionKey))));
			res.add(new String(Base64.encode(encSessionKey)));
			return res;
		} catch (UnsupportedEncodingException e) {

			throw new CryptoUtilsException("RSA Encryption error: " + e,
					e);
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see cinvestav.cryptography.android.utils.IAsymmetricCryptoUtils#
	 * decrypt(byte[], org.spongycastle.crypto.params.RSAKeyParameters,
	 * java.lang.String)
	 */
	@Override
	public byte[] decrypt(byte[] cipherText, byte[] encSessionKey,
			RSAPrivateKey privateKey, String operationMode)
			throws CryptoUtilsException {

		// Decrypt the session Key using ECIES
		byte[] sessionKey = rsa.decrypt(encSessionKey, privateKey,
				operationMode);

		// Decrypt the input message
		return androidSymmetricCryptoUtils.aes_decrypt(256,cipherText, sessionKey);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see cinvestav.cryptography.android.utils.IAsymmetricCryptoUtils#
	 * decrypt(byte[], org.spongycastle.crypto.params.RSAKeyParameters)
	 */
	@Override
	public byte[] decrypt(byte[] cipherText, byte[] encSessionKey,
			RSAPrivateKey privateKey) throws CryptoUtilsException {

		// Decrypt the session Key using ECIES
		byte[] sessionKey = rsa.decrypt(encSessionKey, privateKey,
				RSA.OPERATION_MODE_PKCS1);

		// Decrypt the input message
		return androidSymmetricCryptoUtils.aes_decrypt(256,cipherText, sessionKey);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see cinvestav.cryptography.android.utils.IAsymmetricCryptoUtils#
	 * decrypt(java.lang.String,
	 * org.spongycastle.crypto.params.RSAKeyParameters, java.lang.String,
	 * java.lang.String)
	 */
	@Override
	public String decrypt(String cipherText, String encSessionKey,
			RSAPrivateKey privateKey, String encoder, String operationMode)
			throws CryptoUtilsException {
		if (encoder.equalsIgnoreCase(CryptoUtils.ENCODER_BASE64)) {
			// Decrypt the session Key using ECIES
			byte[] sessionKey = rsa.decrypt(Base64.decode(encSessionKey),
					privateKey, operationMode);

			// Decrypt the input message
			return new String(
					androidSymmetricCryptoUtils.aes_decrypt(256,Base64.decode(cipherText), sessionKey));

		}
		if (encoder.equalsIgnoreCase(CryptoUtils.ENCODER_HEX)) {
			// Decrypt the session Key using ECIES
			byte[] sessionKey = rsa.decrypt(Hex.decode(encSessionKey),
					privateKey, operationMode);

			// Decrypt the input message
			return new String(androidSymmetricCryptoUtils.aes_decrypt(256,Hex.decode(cipherText), sessionKey));
		}

		throw new CryptoUtilsException(
				"Encryption error: Unsupported encoder [" + encoder + "]");
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see cinvestav.cryptography.android.utils.IAsymmetricCryptoUtils#
	 * decrypt(java.lang.String,
	 * org.spongycastle.crypto.params.RSAKeyParameters, java.lang.String)
	 */
	@Override
	public String decrypt(String cipherText, String encSessionKey,
			RSAPrivateKey privateKey, String encoder)
			throws CryptoUtilsException {
		if (encoder.equalsIgnoreCase(CryptoUtils.ENCODER_BASE64)) {
			// Decrypt the session Key using ECIES
			byte[] sessionKey = rsa.decrypt(Base64.decode(encSessionKey),
					privateKey, RSA.OPERATION_MODE_PKCS1);

			// Decrypt the input message
			return new String(
					androidSymmetricCryptoUtils.aes_decrypt(256,Base64.decode(cipherText), sessionKey));

		}
		if (encoder.equalsIgnoreCase(CryptoUtils.ENCODER_HEX)) {
			// Decrypt the session Key using ECIES
			byte[] sessionKey = rsa.decrypt(Hex.decode(encSessionKey),
					privateKey, RSA.OPERATION_MODE_PKCS1);

			// Decrypt the input message
			return new String(androidSymmetricCryptoUtils.aes_decrypt(256,Hex.decode(cipherText), sessionKey));
		}

		throw new CryptoUtilsException(
				"Encryption error: Unsupported encoder [" + encoder + "]");
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see cinvestav.cryptography.android.utils.IAsymmetricCryptoUtils#
	 * decrypt(java.lang.String,
	 * org.spongycastle.crypto.params.RSAKeyParameters)
	 */
	@Override
	public String decrypt(String cipherText, String encSessionKey,
			RSAPrivateKey privateKey) throws CryptoUtilsException {

		// Decrypt the session Key using ECIES
		byte[] sessionKey = rsa.decrypt(Base64.decode(encSessionKey),
				privateKey, RSA.OPERATION_MODE_PKCS1);

		// Decrypt the input message
		return new String(androidSymmetricCryptoUtils.aes_decrypt(256,Base64.decode(cipherText), sessionKey));

	}

	/* (non-Javadoc)
	 * @see cinvestav.android.pki.cryptography.utils.IAsymmetricCryptoUtils#generateKeys(int)
	 */
	@Override
	public RSAKeyPair generateKeys(int keySizeInBits) throws CryptoUtilsException {
		return rsa.generateKeys(keySizeInBits);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IAsymmetricCryptoUtils
	 * #sign(byte[], cinvestav.android.pki.cryptography.key.RSAPrivateKey,
	 * java.lang.String)
	 */
	@Override
	public byte[] sign(byte[] message, RSAPrivateKey privateKey,
			String digestName) throws CryptoUtilsException {
		return rsa.sign(message, privateKey, digestName);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IAsymmetricCryptoUtils
	 * #sign(byte[], cinvestav.android.pki.cryptography.key.RSAPrivateKey)
	 */
	@Override
	public byte[] sign(byte[] message, RSAPrivateKey privateKey)
			throws CryptoUtilsException {
		return rsa.sign(message, privateKey);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IAsymmetricCryptoUtils
	 * #sign(java.lang.String,
	 * cinvestav.android.pki.cryptography.key.RSAPrivateKey, java.lang.String,
	 * java.lang.String)
	 */
	@Override
	public String sign(String message, RSAPrivateKey privateKey,
			String digestName, String encoder)
			throws CryptoUtilsException {
		try {
			if (encoder.equalsIgnoreCase(CryptoUtils.ENCODER_BASE64)) {
				return new String(Base64.encode(rsa.sign(
						message.getBytes("UTF-8"), privateKey, digestName)));
			}
			if (encoder.equalsIgnoreCase(CryptoUtils.ENCODER_HEX)) {
				return new String(Hex.encode(rsa.sign(
						message.getBytes("UTF-8"), privateKey, digestName)));
			}

			throw new CryptoUtilsException(
					"Sign error: Unsupported encoder [" + encoder + "]");
		} catch (UnsupportedEncodingException e) {

			throw new CryptoUtilsException(e.getMessage(), e);
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IAsymmetricCryptoUtils
	 * #sign(java.lang.String,
	 * cinvestav.android.pki.cryptography.key.RSAPrivateKey, java.lang.String)
	 */
	@Override
	public String sign(String message, RSAPrivateKey privateKey,
			String digestName) throws CryptoUtilsException {
		try {

			return new String(Base64.encode(rsa.sign(message.getBytes("UTF-8"),
					privateKey, digestName)));
		} catch (UnsupportedEncodingException e) {

			throw new CryptoUtilsException(e.getMessage(), e);
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IAsymmetricCryptoUtils
	 * #sign(java.lang.String,
	 * cinvestav.android.pki.cryptography.key.RSAPrivateKey)
	 */
	@Override
	public String sign(String message, RSAPrivateKey privateKey)
			throws CryptoUtilsException {
		try {

			return new String(Base64.encode(rsa.sign(message.getBytes("UTF-8"),
					privateKey)));
		} catch (UnsupportedEncodingException e) {

			throw new CryptoUtilsException(e.getMessage(), e);
		}

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IAsymmetricCryptoUtils
	 * #verify(byte[], byte[],
	 * cinvestav.android.pki.cryptography.key.RSAPublicKey, java.lang.String)
	 */
	@Override
	public Boolean verify(byte[] message, byte[] sign,
			RSAPublicKey publicKey, String digestName)
			throws CryptoUtilsException {
		return rsa.verify(message, sign, publicKey, digestName);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IAsymmetricCryptoUtils
	 * #verify(byte[], byte[],
	 * cinvestav.android.pki.cryptography.key.RSAPublicKey)
	 */
	@Override
	public Boolean verify(byte[] message, byte[] sign,
			RSAPublicKey publicKey) throws CryptoUtilsException {
		return rsa.verify(message, sign, publicKey);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IAsymmetricCryptoUtils
	 * #verify(java.lang.String, java.lang.String,
	 * cinvestav.android.pki.cryptography.key.RSAPublicKey, java.lang.String,
	 * java.lang.String)
	 */
	@Override
	public Boolean verify(String message, String sign,
			RSAPublicKey publicKey, String digestName, String encoder)
			throws CryptoUtilsException {
		try {
			if (encoder.equalsIgnoreCase(CryptoUtils.ENCODER_BASE64)) {
				return rsa.verify(message.getBytes("UTF-8"),
						Base64.decode(sign), publicKey, digestName);
			}
			if (encoder.equalsIgnoreCase(CryptoUtils.ENCODER_HEX)) {
				return rsa.verify(message.getBytes("UTF-8"), Hex.decode(sign),
						publicKey, digestName);
			}

			throw new CryptoUtilsException(
					"Verify error: Unsupported encoder [" + encoder + "]");
		} catch (UnsupportedEncodingException e) {

			throw new CryptoUtilsException(e.getMessage(), e);
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IAsymmetricCryptoUtils
	 * #verify(java.lang.String, java.lang.String,
	 * cinvestav.android.pki.cryptography.key.RSAPublicKey, java.lang.String)
	 */
	@Override
	public Boolean verify(String message, String sign,
			RSAPublicKey publicKey, String digestName)
			throws CryptoUtilsException {

		try {

			return rsa.verify(message.getBytes("UTF-8"), Base64.decode(sign),
					publicKey, digestName);
		} catch (UnsupportedEncodingException e) {

			throw new CryptoUtilsException(e.getMessage(), e);
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IAsymmetricCryptoUtils
	 * #verify(java.lang.String, java.lang.String,
	 * cinvestav.android.pki.cryptography.key.RSAPublicKey)
	 */
	@Override
	public Boolean verify(String message, String sign,
			RSAPublicKey publicKey) throws CryptoUtilsException {
		try {

			return rsa.verify(message.getBytes("UTF-8"), Base64.decode(sign),
					publicKey);
		} catch (UnsupportedEncodingException e) {

			throw new CryptoUtilsException(e.getMessage(), e);
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IAsymmetricCryptoUtils
	 * #generateKeys
	 * (cinvestav.android.pki.cryptography.ec.ECDomainParameters)
	 */
	@Override
	public ECKeyPair generateKeys(ECDomainParameters parameters)
			throws CryptoUtilsException {

		return ec.generateKeys(parameters);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IAsymmetricCryptoUtils
	 * #generateKeys(java.lang.String)
	 */
	@Override
	public ECKeyPair generateKeys(String nistCurveName)
			throws CryptoUtilsException {

		return ec.generateKeys(ECDomainParameters
				.getByNistECName(nistCurveName));
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IAsymmetricCryptoUtils
	 * #sign(byte[], cinvestav.android.pki.cryptography.key.ECPrivateKey,
	 * java.lang.String)
	 */
	@Override
	public BigInteger[] sign(byte[] message, ECPrivateKey privateKey,
			String digestName) throws CryptoUtilsException {

		return ec.sign(message, privateKey, digestName);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IAsymmetricCryptoUtils
	 * #sign(java.lang.String,
	 * cinvestav.android.pki.cryptography.key.ECPrivateKey, java.lang.String)
	 */
	@Override
	public BigInteger[] sign(String message, ECPrivateKey privateKey,
			String digestName) throws CryptoUtilsException {

		return ec.sign(message.getBytes(), privateKey, digestName);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IAsymmetricCryptoUtils
	 * #sign(byte[], cinvestav.android.pki.cryptography.key.ECPrivateKey)
	 */
	@Override
	public BigInteger[] sign(byte[] message, ECPrivateKey privateKey)
			throws CryptoUtilsException {

		return ec.sign(message, privateKey,
				CryptoUtils.DIGEST_FUNCTION_SHA_1);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IAsymmetricCryptoUtils
	 * #sign(java.lang.String,
	 * cinvestav.android.pki.cryptography.key.ECPrivateKey)
	 */
	@Override
	public BigInteger[] sign(String message, ECPrivateKey privateKey)
			throws CryptoUtilsException {

		return ec.sign(message.getBytes(), privateKey,
				CryptoUtils.DIGEST_FUNCTION_SHA_1);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IAsymmetricCryptoUtils
	 * #verify(byte[], java.math.BigInteger[],
	 * cinvestav.android.pki.cryptography.key.ECPublicKey, java.lang.String)
	 */
	@Override
	public Boolean verify(byte[] message, BigInteger[] sig,
			ECPublicKey publicKey, String digestName)
			throws CryptoUtilsException {

		return ec.verify(message, sig, publicKey, digestName);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IAsymmetricCryptoUtils
	 * #verify(byte[], java.math.BigInteger[],
	 * cinvestav.android.pki.cryptography.key.ECPublicKey)
	 */
	@Override
	public Boolean verify(byte[] message, BigInteger[] sig,
			ECPublicKey publicKey) throws CryptoUtilsException {

		return ec.verify(message, sig, publicKey,
				CryptoUtils.DIGEST_FUNCTION_SHA_1);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IAsymmetricCryptoUtils
	 * #verify(java.lang.String, java.math.BigInteger[],
	 * cinvestav.android.pki.cryptography.key.ECPublicKey, java.lang.String)
	 */
	@Override
	public Boolean verify(String message, BigInteger[] sig,
			ECPublicKey publicKey, String digestName)
			throws CryptoUtilsException {

		return ec.verify(message.getBytes(), sig, publicKey, digestName);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IAsymmetricCryptoUtils
	 * #verify(java.lang.String, java.math.BigInteger[],
	 * cinvestav.android.pki.cryptography.key.ECPublicKey)
	 */
	@Override
	public Boolean verify(String message, BigInteger[] sig,
			ECPublicKey publicKey) throws CryptoUtilsException {

		return ec.verify(message.getBytes(), sig, publicKey,
				CryptoUtils.DIGEST_FUNCTION_SHA_1);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IAsymmetricCryptoUtils
	 * #encrypt(byte[], cinvestav.android.pki.cryptography.key.ECPublicKey,
	 * cinvestav.android.pki.cryptography.key.ECPrivateKey, byte[], byte[], int,
	 * int)
	 */
	@Override
	public List<byte[]> encrypt(byte[] input,
			ECPublicKey receiverPartPublicKey, ECPrivateKey ownPrivateKey,
			byte[] derivation, byte[] encoding, int macSize, int keySize)
			throws CryptoUtilsException {

		// Create a random 256 bits sessionKey
		byte[] sessionKey = androidSymmetricCryptoUtils.aes_generateKey(256);
		

		// Encrypt session key using EC IES
		byte[] encSessionKey = ec.encrypt(sessionKey, receiverPartPublicKey,
				ownPrivateKey, derivation, encoding, macSize, keySize);

		// Create return list and fill it
		List<byte[]> res = new LinkedList<byte[]>();
		// Use the encrypted session key to encrypt the original input
		res.add(androidSymmetricCryptoUtils.aes_encrypt(256,input, sessionKey));
		res.add(encSessionKey);
		return res;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IAsymmetricCryptoUtils
	 * #encrypt(byte[], cinvestav.android.pki.cryptography.key.ECPublicKey,
	 * cinvestav.android.pki.cryptography.key.ECPrivateKey, int, int)
	 */
	@Override
	public List<byte[]> encrypt(byte[] input,
			ECPublicKey receiverPartPublicKey, ECPrivateKey ownPrivateKey,
			int macSize, int keySize) throws CryptoUtilsException {

		// Create a random 256 bits sessionKey
		byte[] sessionKey = androidSymmetricCryptoUtils.aes_generateKey(256);
		

		// Encrypt session key using EC IES
		byte[] encSessionKey = ec.encrypt(sessionKey, receiverPartPublicKey,
				ownPrivateKey, macSize, keySize);

		// Create return list and fill it
		List<byte[]> res = new LinkedList<byte[]>();
		// Use the encrypted session key to encrypt the original input
		res.add(androidSymmetricCryptoUtils.aes_encrypt(256,input, sessionKey));
		res.add(encSessionKey);
		return res;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IAsymmetricCryptoUtils
	 * #encrypt(byte[], cinvestav.android.pki.cryptography.key.ECPublicKey,
	 * cinvestav.android.pki.cryptography.key.ECPrivateKey, int)
	 */
	@Override
	public List<byte[]> encrypt(byte[] input,
			ECPublicKey receiverPartPublicKey, ECPrivateKey ownPrivateKey,
			int keySize) throws CryptoUtilsException {

		// Create a random 256 bits sessionKey
		byte[] sessionKey = androidSymmetricCryptoUtils.aes_generateKey(256);
		

		// Encrypt session key using EC IES
		byte[] encSessionKey = ec.encrypt(sessionKey, receiverPartPublicKey,
				ownPrivateKey, keySize);

		// Create return list and fill it
		List<byte[]> res = new LinkedList<byte[]>();
		// Use the encrypted session key to encrypt the original input
		res.add(androidSymmetricCryptoUtils.aes_encrypt(256,input, sessionKey));
		res.add(encSessionKey);
		return res;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IAsymmetricCryptoUtils
	 * #encrypt(byte[], cinvestav.android.pki.cryptography.key.ECPublicKey,
	 * cinvestav.android.pki.cryptography.key.ECPrivateKey)
	 */
	@Override
	public List<byte[]> encrypt(byte[] input,
			ECPublicKey receiverPartPublicKey, ECPrivateKey ownPrivateKey)
			throws CryptoUtilsException {

		// Create a random 256 bits sessionKey
		byte[] sessionKey = androidSymmetricCryptoUtils.aes_generateKey(256);
		

		// Encrypt session key using EC IES
		byte[] encSessionKey = ec.encrypt(sessionKey, receiverPartPublicKey,
				ownPrivateKey);

		// Create return list and fill it
		List<byte[]> res = new LinkedList<byte[]>();
		// Use the encrypted session key to encrypt the original input
		res.add(androidSymmetricCryptoUtils.aes_encrypt(256,input, sessionKey));
		res.add(encSessionKey);
		return res;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IAsymmetricCryptoUtils
	 * #decrypt(byte[], byte[],
	 * cinvestav.android.pki.cryptography.key.ECPublicKey,
	 * cinvestav.android.pki.cryptography.key.ECPrivateKey, byte[], byte[], int,
	 * int)
	 */
	@Override
	public byte[] decrypt(byte[] input, byte[] encSessionKey,
			ECPublicKey senderPartPublicKey, ECPrivateKey ownPrivateKey,
			byte[] derivation, byte[] encoding, int macSize, int keySize)
			throws CryptoUtilsException {

		// Decrypt the session Key using ECIES
		byte[] sessionKey = ec.decrypt(encSessionKey, senderPartPublicKey,
				ownPrivateKey, derivation, encoding, macSize, keySize);

		// Decrypt the input message
		return androidSymmetricCryptoUtils.aes_decrypt(256,input, sessionKey);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IAsymmetricCryptoUtils
	 * #decrypt(byte[], byte[],
	 * cinvestav.android.pki.cryptography.key.ECPublicKey,
	 * cinvestav.android.pki.cryptography.key.ECPrivateKey, int, int)
	 */
	@Override
	public byte[] decrypt(byte[] input, byte[] encSessionKey,
			ECPublicKey senderPartPublicKey, ECPrivateKey ownPrivateKey,
			int macSize, int keySize) throws CryptoUtilsException {
		// Decrypt the session Key using ECIES
		byte[] sessionKey = ec.decrypt(encSessionKey, senderPartPublicKey,
				ownPrivateKey, macSize, keySize);

		// Decrypt the input message
		return androidSymmetricCryptoUtils.aes_decrypt(256,input, sessionKey);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IAsymmetricCryptoUtils
	 * #decrypt(byte[], byte[],
	 * cinvestav.android.pki.cryptography.key.ECPublicKey,
	 * cinvestav.android.pki.cryptography.key.ECPrivateKey, int)
	 */
	@Override
	public byte[] decrypt(byte[] input, byte[] encSessionKey,
			ECPublicKey senderPartPublicKey, ECPrivateKey ownPrivateKey,
			int keySize) throws CryptoUtilsException {
		// Decrypt the session Key using ECIES
		byte[] sessionKey = ec.decrypt(encSessionKey, senderPartPublicKey,
				ownPrivateKey, keySize);

		// Decrypt the input message
		return androidSymmetricCryptoUtils.aes_decrypt(256,input, sessionKey);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IAsymmetricCryptoUtils
	 * #decrypt(byte[], byte[],
	 * cinvestav.android.pki.cryptography.key.ECPublicKey,
	 * cinvestav.android.pki.cryptography.key.ECPrivateKey)
	 */
	@Override
	public byte[] decrypt(byte[] input, byte[] encSessionKey,
			ECPublicKey senderPartPublicKey, ECPrivateKey ownPrivateKey)
			throws CryptoUtilsException {
		// Decrypt the session Key using ECIES
		byte[] sessionKey = ec.decrypt(encSessionKey, senderPartPublicKey,
				ownPrivateKey);

		// Decrypt the input message
		return androidSymmetricCryptoUtils.aes_decrypt(256,input, sessionKey);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IAsymmetricCryptoUtils
	 * #encrypt(java.lang.String,
	 * cinvestav.android.pki.cryptography.key.ECPublicKey,
	 * cinvestav.android.pki.cryptography.key.ECPrivateKey, byte[], byte[], int,
	 * int, java.lang.String)
	 */
	@Override
	public List<String> encrypt(String input,
			ECPublicKey receiverPartPublicKey, ECPrivateKey ownPrivateKey,
			byte[] derivation, byte[] encoding, int macSize, int keySize,
			String encoder) throws CryptoUtilsException {

		try {
			String encSessionKeyStr = "";

			// Create a random 256 bits sessionKey
			byte[] sessionKey = androidSymmetricCryptoUtils.aes_generateKey(256);
			

			byte[] encSessionKey;

			// Create return list and fill it
			List<String> res = new LinkedList<String>();

			if (encoder.equalsIgnoreCase(CryptoUtils.ENCODER_BASE64)) {

				// Encrypt session key using EC IES
				encSessionKey = ec.encrypt(sessionKey, receiverPartPublicKey,
						ownPrivateKey, derivation, encoding, macSize, keySize);

				encSessionKeyStr = new String(Base64.encode(encSessionKey));

				// Use the encrypted session key to encrypt the original input
				res.add(new String(Base64.encode(androidSymmetricCryptoUtils.aes_encrypt(256,
						input.getBytes("UTF-8"), sessionKey))));
				res.add(encSessionKeyStr);
				return res;
			}
			if (encoder.equalsIgnoreCase(CryptoUtils.ENCODER_HEX)) {

				// Encrypt session key using EC IES
				encSessionKey = ec.encrypt(sessionKey, receiverPartPublicKey,
						ownPrivateKey, derivation, encoding, macSize, keySize);

				encSessionKeyStr = new String(Hex.encode(encSessionKey));

				// Use the encrypted session key to encrypt the original input
				res.add(new String(Hex.encode(androidSymmetricCryptoUtils.aes_encrypt(256,
						input.getBytes("UTF-8"), sessionKey))));
				res.add(encSessionKeyStr);
				return res;
			}

			throw new CryptoUtilsException(
					"Encryption error: Unsupported encoder [" + encoder + "]");
		} catch (UnsupportedEncodingException e) {
			throw new CryptoUtilsException("EC Encryption error: " + e,
					e);
		}

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IAsymmetricCryptoUtils
	 * #encrypt(java.lang.String,
	 * cinvestav.android.pki.cryptography.key.ECPublicKey,
	 * cinvestav.android.pki.cryptography.key.ECPrivateKey, int, int,
	 * java.lang.String)
	 */
	@Override
	public List<String> encrypt(String input,
			ECPublicKey receiverPartPublicKey, ECPrivateKey ownPrivateKey,
			int macSize, int keySize, String encoder)
			throws CryptoUtilsException {

		try {
			String encSessionKeyStr = "";

			// Create a random 256 bits sessionKey
			byte[] sessionKey = androidSymmetricCryptoUtils.aes_generateKey(256);
			

			byte[] encSessionKey;

			// Create return list and fill it
			List<String> res = new LinkedList<String>();

			if (encoder.equalsIgnoreCase(CryptoUtils.ENCODER_BASE64)) {

				// Encrypt session key using EC IES
				encSessionKey = ec.encrypt(sessionKey, receiverPartPublicKey,
						ownPrivateKey, macSize, keySize);

				encSessionKeyStr = new String(Base64.encode(encSessionKey));

				// Use the encrypted session key to encrypt the original input
				res.add(new String(Base64.encode(androidSymmetricCryptoUtils.aes_encrypt(256,
						input.getBytes("UTF-8"), sessionKey))));
				res.add(encSessionKeyStr);
				return res;
			}
			if (encoder.equalsIgnoreCase(CryptoUtils.ENCODER_HEX)) {

				// Encrypt session key using EC IES
				encSessionKey = ec.encrypt(sessionKey, receiverPartPublicKey,
						ownPrivateKey, macSize, keySize);

				encSessionKeyStr = new String(Hex.encode(encSessionKey));

				// Use the encrypted session key to encrypt the original input
				res.add(new String(Hex.encode(androidSymmetricCryptoUtils.aes_encrypt(256,
						input.getBytes("UTF-8"), sessionKey))));
				res.add(encSessionKeyStr);
				return res;
			}

			throw new CryptoUtilsException(
					"Encryption error: Unsupported encoder [" + encoder + "]");
		} catch (UnsupportedEncodingException e) {
			throw new CryptoUtilsException("EC Encryption error: " + e,
					e);
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IAsymmetricCryptoUtils
	 * #encrypt(java.lang.String,
	 * cinvestav.android.pki.cryptography.key.ECPublicKey,
	 * cinvestav.android.pki.cryptography.key.ECPrivateKey, int,
	 * java.lang.String)
	 */
	@Override
	public List<String> encrypt(String input,
			ECPublicKey receiverPartPublicKey, ECPrivateKey ownPrivateKey,
			int keySize, String encoder) throws CryptoUtilsException {

		try {
			String encSessionKeyStr = "";

			// Create a random 256 bits sessionKey
			byte[] sessionKey = androidSymmetricCryptoUtils.aes_generateKey(256);
			

			byte[] encSessionKey;

			// Create return list and fill it
			List<String> res = new LinkedList<String>();

			if (encoder.equalsIgnoreCase(CryptoUtils.ENCODER_BASE64)) {

				// Encrypt session key using EC IES
				encSessionKey = ec.encrypt(sessionKey, receiverPartPublicKey,
						ownPrivateKey, keySize);

				encSessionKeyStr = new String(Base64.encode(encSessionKey));

				// Use the encrypted session key to encrypt the original input
				res.add(new String(Base64.encode(androidSymmetricCryptoUtils.aes_encrypt(256,
						input.getBytes("UTF-8"), sessionKey))));
				res.add(encSessionKeyStr);
				return res;
			}
			if (encoder.equalsIgnoreCase(CryptoUtils.ENCODER_HEX)) {

				// Encrypt session key using EC IES
				encSessionKey = ec.encrypt(sessionKey, receiverPartPublicKey,
						ownPrivateKey, keySize);

				encSessionKeyStr = new String(Hex.encode(encSessionKey));

				// Use the encrypted session key to encrypt the original input
				res.add(new String(Hex.encode(androidSymmetricCryptoUtils.aes_encrypt(256,
						input.getBytes("UTF-8"), sessionKey))));
				res.add(encSessionKeyStr);
				return res;
			}

			throw new CryptoUtilsException(
					"Encryption error: Unsupported encoder [" + encoder + "]");
		} catch (UnsupportedEncodingException e) {
			throw new CryptoUtilsException("EC Encryption error: " + e,
					e);
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IAsymmetricCryptoUtils
	 * #encrypt(java.lang.String,
	 * cinvestav.android.pki.cryptography.key.ECPublicKey,
	 * cinvestav.android.pki.cryptography.key.ECPrivateKey, java.lang.String)
	 */
	@Override
	public List<String> encrypt(String input,
			ECPublicKey receiverPartPublicKey, ECPrivateKey ownPrivateKey,
			String encoder) throws CryptoUtilsException {

		try {
			String encSessionKeyStr = "";

			// Create a random 256 bits sessionKey
			byte[] sessionKey = androidSymmetricCryptoUtils.aes_generateKey(256);

			byte[] encSessionKey;

			// Create return list and fill it
			List<String> res = new LinkedList<String>();

			if (encoder.equalsIgnoreCase(CryptoUtils.ENCODER_BASE64)) {

				// Encrypt session key using EC IES
				encSessionKey = ec.encrypt(sessionKey, receiverPartPublicKey,
						ownPrivateKey);

				encSessionKeyStr = new String(Base64.encode(encSessionKey));

				// Use the encrypted session key to encrypt the original input
				res.add(new String(Base64.encode(androidSymmetricCryptoUtils.aes_encrypt(256,
						input.getBytes("UTF-8"), sessionKey))));
				res.add(encSessionKeyStr);
				return res;
			}
			if (encoder.equalsIgnoreCase(CryptoUtils.ENCODER_HEX)) {

				// Encrypt session key using EC IES
				encSessionKey = ec.encrypt(sessionKey, receiverPartPublicKey,
						ownPrivateKey);

				encSessionKeyStr = new String(Hex.encode(encSessionKey));

				// Use the encrypted session key to encrypt the original input
				res.add(new String(Hex.encode(androidSymmetricCryptoUtils.aes_encrypt(256,
						input.getBytes("UTF-8"), sessionKey))));
				res.add(encSessionKeyStr);
				return res;
			}

			throw new CryptoUtilsException(
					"Encryption error: Unsupported encoder [" + encoder + "]");
		} catch (UnsupportedEncodingException e) {
			throw new CryptoUtilsException("EC Encryption error: " + e,
					e);
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IAsymmetricCryptoUtils
	 * #encrypt(java.lang.String,
	 * cinvestav.android.pki.cryptography.key.ECPublicKey,
	 * cinvestav.android.pki.cryptography.key.ECPrivateKey)
	 */
	@Override
	public List<String> encrypt(String input,
			ECPublicKey receiverPartPublicKey, ECPrivateKey ownPrivateKey)
			throws CryptoUtilsException {

		try {
			String encSessionKeyStr = "";

			// Create a random 256 bits sessionKey
			byte[] sessionKey = androidSymmetricCryptoUtils.aes_generateKey(256);
			

			byte[] encSessionKey;

			// Create return list and fill it
			List<String> res = new LinkedList<String>();

			// Encrypt session key using EC IES
			encSessionKey = ec.encrypt(sessionKey, receiverPartPublicKey,
					ownPrivateKey);

			encSessionKeyStr = new String(Base64.encode(encSessionKey));

			// Use the encrypted session key to encrypt the original input
			res.add(new String(Base64.encode(androidSymmetricCryptoUtils.aes_encrypt(256,
					input.getBytes("UTF-8"), sessionKey))));
			res.add(encSessionKeyStr);
			return res;

		} catch (UnsupportedEncodingException e) {
			throw new CryptoUtilsException("EC Encryption error: " + e,
					e);
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IAsymmetricCryptoUtils
	 * #decrypt(java.lang.String, java.lang.String,
	 * cinvestav.android.pki.cryptography.key.ECPublicKey,
	 * cinvestav.android.pki.cryptography.key.ECPrivateKey, byte[], byte[], int,
	 * int, java.lang.String)
	 */
	@Override
	public String decrypt(String input, String encSessionKey,
			ECPublicKey senderPartPublicKey, ECPrivateKey ownPrivateKey,
			byte[] derivation, byte[] encoding, int macSize, int keySize,
			String encoder) throws CryptoUtilsException {

		byte[] sessionKey;

		if (encoder.equalsIgnoreCase(CryptoUtils.ENCODER_BASE64)) {

			// Decrypt the session Key using ECIES
			sessionKey = ec.decrypt(Base64.decode(encSessionKey),
					senderPartPublicKey, ownPrivateKey, derivation, encoding,
					macSize, keySize);

			// Decrypt the input message
			return new String(androidSymmetricCryptoUtils.aes_decrypt(256,Base64.decode(input), sessionKey));

		}
		if (encoder.equalsIgnoreCase(CryptoUtils.ENCODER_HEX)) {
			// Decrypt the session Key using ECIES
			sessionKey = ec.decrypt(Hex.decode(encSessionKey),
					senderPartPublicKey, ownPrivateKey, derivation, encoding,
					macSize, keySize);

			// Decrypt the input message
			return new String(androidSymmetricCryptoUtils.aes_decrypt(256,Hex.decode(input), sessionKey));
		}

		throw new CryptoUtilsException(
				"Decryption error: Unsupported encoder [" + encoder + "]");
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IAsymmetricCryptoUtils
	 * #decrypt(java.lang.String, java.lang.String,
	 * cinvestav.android.pki.cryptography.key.ECPublicKey,
	 * cinvestav.android.pki.cryptography.key.ECPrivateKey, int, int,
	 * java.lang.String)
	 */
	@Override
	public String decrypt(String input, String encSessionKey,
			ECPublicKey senderPartPublicKey, ECPrivateKey ownPrivateKey,
			int macSize, int keySize, String encoder)
			throws CryptoUtilsException {

		byte[] sessionKey;

		if (encoder.equalsIgnoreCase(CryptoUtils.ENCODER_BASE64)) {

			// Decrypt the session Key using ECIES
			sessionKey = ec.decrypt(Base64.decode(encSessionKey),
					senderPartPublicKey, ownPrivateKey, macSize, keySize);

			// Decrypt the input message
			return new String(androidSymmetricCryptoUtils.aes_decrypt(256,Base64.decode(input), sessionKey));

		}
		if (encoder.equalsIgnoreCase(CryptoUtils.ENCODER_HEX)) {
			// Decrypt the session Key using ECIES
			sessionKey = ec.decrypt(Hex.decode(encSessionKey),
					senderPartPublicKey, ownPrivateKey, macSize, keySize);

			// Decrypt the input message
			return new String(androidSymmetricCryptoUtils.aes_decrypt(256,Hex.decode(input), sessionKey));
		}

		throw new CryptoUtilsException(
				"Decryption error: Unsupported encoder [" + encoder + "]");
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IAsymmetricCryptoUtils
	 * #decrypt(java.lang.String, java.lang.String,
	 * cinvestav.android.pki.cryptography.key.ECPublicKey,
	 * cinvestav.android.pki.cryptography.key.ECPrivateKey, int,
	 * java.lang.String)
	 */
	@Override
	public String decrypt(String input, String encSessionKey,
			ECPublicKey senderPartPublicKey, ECPrivateKey ownPrivateKey,
			int keySize, String encoder) throws CryptoUtilsException {

		byte[] sessionKey;

		if (encoder.equalsIgnoreCase(CryptoUtils.ENCODER_BASE64)) {

			// Decrypt the session Key using ECIES
			sessionKey = ec.decrypt(Base64.decode(encSessionKey),
					senderPartPublicKey, ownPrivateKey, keySize);

			// Decrypt the input message
			return new String(androidSymmetricCryptoUtils.aes_decrypt(256,Base64.decode(input), sessionKey));

		}
		if (encoder.equalsIgnoreCase(CryptoUtils.ENCODER_HEX)) {
			// Decrypt the session Key using ECIES
			sessionKey = ec.decrypt(Hex.decode(encSessionKey),
					senderPartPublicKey, ownPrivateKey, keySize);

			// Decrypt the input message
			return new String(androidSymmetricCryptoUtils.aes_decrypt(256,Hex.decode(input), sessionKey));
		}

		throw new CryptoUtilsException(
				"Decryption error: Unsupported encoder [" + encoder + "]");
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IAsymmetricCryptoUtils
	 * #decrypt(java.lang.String, java.lang.String,
	 * cinvestav.android.pki.cryptography.key.ECPublicKey,
	 * cinvestav.android.pki.cryptography.key.ECPrivateKey, java.lang.String)
	 */
	@Override
	public String decrypt(String input, String encSessionKey,
			ECPublicKey senderPartPublicKey, ECPrivateKey ownPrivateKey,
			String encoder) throws CryptoUtilsException {

		byte[] sessionKey;

		if (encoder.equalsIgnoreCase(CryptoUtils.ENCODER_BASE64)) {

			// Decrypt the session Key using ECIES
			sessionKey = ec.decrypt(Base64.decode(encSessionKey),
					senderPartPublicKey, ownPrivateKey);

			// Decrypt the input message
			return new String(androidSymmetricCryptoUtils.aes_decrypt(256,Base64.decode(input), sessionKey));

		}
		if (encoder.equalsIgnoreCase(CryptoUtils.ENCODER_HEX)) {
			// Decrypt the session Key using ECIES
			sessionKey = ec.decrypt(Hex.decode(encSessionKey),
					senderPartPublicKey, ownPrivateKey);

			// Decrypt the input message
			return new String(androidSymmetricCryptoUtils.aes_decrypt(256,Hex.decode(input), sessionKey));
		}

		throw new CryptoUtilsException(
				"Decryption error: Unsupported encoder [" + encoder + "]");
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IAsymmetricCryptoUtils
	 * #decrypt(java.lang.String, java.lang.String,
	 * cinvestav.android.pki.cryptography.key.ECPublicKey,
	 * cinvestav.android.pki.cryptography.key.ECPrivateKey)
	 */
	@Override
	public String decrypt(String input, String encSessionKey,
			ECPublicKey senderPartPublicKey, ECPrivateKey ownPrivateKey)
			throws CryptoUtilsException {

		byte[] sessionKey;

		// Decrypt the session Key using ECIES
		sessionKey = ec.decrypt(Base64.decode(encSessionKey),
				senderPartPublicKey, ownPrivateKey);

		// Decrypt the input message
		return new String(androidSymmetricCryptoUtils.aes_decrypt(256,Base64.decode(input), sessionKey));
	}

}
