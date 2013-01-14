/**
 *  Created on  : 07/05/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	RSA public key abstraction
 */
package cinvestav.android.pki.cryptography.key;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

import org.spongycastle.crypto.params.RSAKeyParameters;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.util.encoders.Base64;
import org.spongycastle.util.encoders.Hex;

import cinvestav.android.pki.cryptography.exception.CryptoUtilsException;
import cinvestav.android.pki.cryptography.utils.CryptoUtils;

/**
 * @author Ing. Javier Silva Pérez - [javier]
 * 
 */
public class RSAPublicKey {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}
	private BigInteger modulus;
	private BigInteger publicExponent;

	/**
	 * Default constructor, initialize modulus and publicExponent in 0
	 */
	public RSAPublicKey() {
		super();
		this.modulus = new BigInteger("0");
		this.publicExponent = new BigInteger("0");
	}

	/**
	 * Copy constructor
	 * 
	 * @param rsaPublicKey
	 *            Source
	 */
	public RSAPublicKey(RSAPublicKey rsaPublicKey) {
		this.modulus = new BigInteger(rsaPublicKey.getModulus().toByteArray());
		this.publicExponent = new BigInteger(rsaPublicKey.getPublicExponent()
				.toByteArray());
	}

	/**
	 * Parameterized constructor, gets the modulus and publicExponent
	 * 
	 * @param modulus
	 * @param publicExponent
	 */
	public RSAPublicKey(BigInteger modulus, BigInteger publicExponent) {
		super();
		this.modulus = modulus;
		this.publicExponent = publicExponent;
	}

	public BigInteger getModulus() {
		return modulus;
	}

	public void setModulus(BigInteger modulus) {
		this.modulus = modulus;
	}

	public BigInteger getPublicExponent() {
		return publicExponent;
	}

	public void setPublicExponent(BigInteger publicExponent) {
		this.publicExponent = publicExponent;
	}

	@Override
	public String toString() {
		return "RSAPublicKey [modulus=" + modulus + ", publicExponent="
				+ publicExponent + "]";
	}

	/**
	 * ToString method using a specific encoder
	 * 
	 * @param encoder
	 *            see available encoders in
	 *            {@link cinvestav.android.pki.cryptography.utils.CryptoUtils}
	 * @return String Public Key encoded
	 */
	public String toString(String encoder) {
		if (encoder.equalsIgnoreCase(CryptoUtils.ENCODER_BASE64)) {
			return "RSAPublicKey [modulus="
					+ new String(Base64.encode(modulus.toByteArray()))
					+ ", publicExponent="
					+ new String(Base64.encode(publicExponent.toByteArray()))
					+ "]";

		}
		if (encoder.equalsIgnoreCase(CryptoUtils.ENCODER_HEX)) {
			return "RSAPublicKey [modulus="
					+ new String(Hex.encode(modulus.toByteArray()))
					+ ", publicExponent="
					+ new String(Hex.encode(publicExponent.toByteArray()))
					+ "]";
		}
		return "RSAPublicKey [modulus=" + modulus + ", publicExponent="
				+ publicExponent + "]";
	}

	@Override
	public boolean equals(Object obj) {
		if (obj instanceof RSAPublicKey) {
			RSAPublicKey key = (RSAPublicKey) obj;
			boolean res = key.modulus.equals(this.modulus)
					&& key.publicExponent.equals(this.publicExponent);
			// && key.version.equals(this.version);
			return res;
		} else {
			return false;
		}
	}

	/**
	 * Parse a {@link org.spongycastle.crypto.params.RSAKeyParameters} and
	 * return new instance of RSA Public Key
	 * 
	 * @param publicKey
	 *            RSAKeyParameters object
	 */
	public static RSAPublicKey parse(RSAKeyParameters publicKey) {
		return new RSAPublicKey(publicKey.getModulus(), publicKey.getExponent());
	}

	/**
	 * Parse an {@link org.spongycastle.asn1.pkcs.RSAPublicKey} object(in pkcs
	 * format) to RSAPublicKey and return instance of RSA Public Key
	 * 
	 * @param publicKey
	 *            RSA Public key to be parsed (
	 *            {@link org.spongycastle.asn1.pkcs.RSAPublicKey})
	 */
	public static RSAPublicKey parse(
			org.spongycastle.asn1.pkcs.RSAPublicKey publicKey) {
		return new RSAPublicKey(publicKey.getModulus(),
				publicKey.getPublicExponent());

	}

	/**
	 * Parse an {@link java.security.interfaces.RSAPublicKey} object to
	 * RSAPublicKey and return new instance of RSA Public Key
	 * 
	 * @param publicKey
	 *            Java default RSA Public Key object
	 */
	public static RSAPublicKey parse(
			java.security.interfaces.RSAPublicKey publicKey) {
		return new RSAPublicKey(publicKey.getModulus(),
				publicKey.getPublicExponent());
	}

	/**
	 * Generic parser, return new instance of RSA Public Key
	 * 
	 * @param publicKey
	 *            Private key object, supported object types are:
	 *            {@link org.spongycastle.crypto.params.RSAKeyParameters} ,
	 *            {@link org.spongycastle.asn1.pkcs.RSAPublicKey},
	 *            {@link java.security.interfaces.RSAPublicKey}
	 * @throws CryptoUtilsException
	 */
	public static RSAPublicKey parse(Object publicKey)
			throws CryptoUtilsException {
		if (publicKey instanceof RSAKeyParameters) {
			return parse((RSAKeyParameters) publicKey);
		} else if (publicKey instanceof org.spongycastle.asn1.pkcs.RSAPublicKey) {
			return parse((org.spongycastle.asn1.pkcs.RSAPublicKey) publicKey);
		} else if (publicKey instanceof java.security.interfaces.RSAPublicKey) {
			return parse((java.security.interfaces.RSAPublicKey) publicKey);
		} else {
			throw new CryptoUtilsException(
					"Parse error: Public key object type not supported");
		}
	}

	/**
	 * Parse the current instance and creates a new instance of
	 * {@link org.spongycastle.crypto.params.RSAKeyParameters}
	 * 
	 * @return New RSAKeyParameters public key with the values of the current
	 *         object
	 */
	public RSAKeyParameters parseToRSAKeyParameters() {
		return new RSAKeyParameters(false, this.modulus, this.publicExponent);
	}

	/**
	 * Parse the current object to
	 * {@link org.spongycastle.asn1.pkcs.RSAPublicKey} (in PKCS format)
	 * 
	 * @return RSAPublicKey in PKCS format
	 */
	public org.spongycastle.asn1.pkcs.RSAPublicKey parseToRSAPublicKey() {
		return new org.spongycastle.asn1.pkcs.RSAPublicKey(this.modulus,
				this.publicExponent);
	}

	/**
	 * Parse the current object to {@link java.security.interfaces.RSAPublicKey}
	 * 
	 * @return RSAPublicKey object compatible with JCE
	 * @throws CryptoUtilsException
	 */
	public java.security.interfaces.RSAPublicKey parseToJCERSAPublicKey()
			throws CryptoUtilsException {
		RSAPublicKeySpec keySpec = new RSAPublicKeySpec(this.modulus,
				this.publicExponent);

		KeyFactory keyFact;
		try {
			keyFact = KeyFactory.getInstance("RSA", CryptoUtils.PROVIDER);
			return (java.security.interfaces.RSAPublicKey) keyFact
					.generatePublic(keySpec);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			throw new CryptoUtilsException("Parse to JCE RSAPublicKey error: "
					+ e, e);
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			throw new CryptoUtilsException("Parse to JCE RSAPublicKey error: "
					+ e, e);
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			throw new CryptoUtilsException("Parse to JCE RSAPublicKey error: "
					+ e, e);
		}
	}

	/**
	 * Save the RSA Private key using DER encoding
	 * 
	 * @param publicKeyFullPath
	 *            Path and name of the file in which the key will be saved
	 * @throws CryptoUtilsException
	 */
	public void saveDER(String publicKeyFullPath) throws CryptoUtilsException {
		byte[] serializedPublicBytes;
		try {
			serializedPublicBytes = this.parseToRSAPublicKey()
					.getEncoded("DER");
			// byte[] key = Base64.encode(serializedPublicBytes);

			File file = new File(publicKeyFullPath);
			FileOutputStream fos = new FileOutputStream(file);
			fos.write(serializedPublicBytes);
			fos.flush();
			fos.close();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			throw new CryptoUtilsException("[savePublicKeyDER]: " + e, e);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			throw new CryptoUtilsException("[savePublicKeyDER]: " + e, e);
		}
	}

	/**
	 * Load the Public key from DER encoded file
	 * 
	 * @param publicKeyFullPath
	 *            Path of the public key
	 * @return Public key read from the file
	 * @throws CryptoUtilsException
	 */
	public static RSAPublicKey loadDER(String publicKeyFullPath)
			throws CryptoUtilsException {
		try {
			File file = new File(publicKeyFullPath);
			if (file.exists()) {
				FileInputStream fis;

				fis = new FileInputStream(file);

				byte[] key = new byte[(int) file.length()];
				fis.read(key);
				fis.close();

				return parse(org.spongycastle.asn1.pkcs.RSAPublicKey
						.getInstance(key));
			} else {
				throw new CryptoUtilsException(
						"RSA Public Key file not found :" + publicKeyFullPath);
			}
		} catch (FileNotFoundException e) {
			throw new CryptoUtilsException("[loadPublicKeyDER]: " + e, e);
		} catch (IOException e) {
			throw new CryptoUtilsException("[loadPublicKeyDER]: " + e, e);
		} catch (IllegalArgumentException e) {
			throw new CryptoUtilsException(
					"Load RSA Public Key from DER file error: " + e, e);
		}
	}

	/**
	 * Encodes this RSAPublicKey object as a base64 encoded byte array using DER
	 * 
	 * @throws CryptoUtilsException
	 */
	public byte[] encode() throws CryptoUtilsException {
		byte[] serializedPublicBytes;
		try {
			serializedPublicBytes = parseToRSAPublicKey().getEncoded("DER");
			return Base64.encode(serializedPublicBytes);
		} catch (IOException e) {
			throw new CryptoUtilsException("Encode RSA Public Key error: " + e,
					e);
		}
	}

	/**
	 * Decodes a byte array encoded using base64 to an RSAPublicKey object
	 * 
	 * @param keyBytes
	 *            Base64 encoded byte array representing the key
	 * @return A new RSAPublicKey that correspond to the encoded bytes
	 * @throws CryptoUtilsException
	 *             if the byte array does not correspond to a Base64
	 *             RSAPublicKey encoded key
	 */
	public static RSAPublicKey decode(byte[] keyBytes)
			throws CryptoUtilsException {
		return parse(org.spongycastle.asn1.pkcs.RSAPublicKey.getInstance(Base64
				.decode(keyBytes)));
	}

}
