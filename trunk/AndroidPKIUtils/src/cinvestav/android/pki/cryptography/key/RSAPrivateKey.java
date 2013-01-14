/**
 *  Created on  : 07/05/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	RSA Private key abstraction
 */
package cinvestav.android.pki.cryptography.key;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.RC2ParameterSpec;

import org.spongycastle.crypto.PBEParametersGenerator;
import org.spongycastle.crypto.generators.OpenSSLPBEParametersGenerator;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.openssl.PEMReader;
import org.spongycastle.openssl.PEMWriter;
import org.spongycastle.openssl.PKCS8Generator;
import org.spongycastle.util.Strings;
import org.spongycastle.util.encoders.Base64;
import org.spongycastle.util.encoders.Hex;

import cinvestav.android.pki.cryptography.exception.CryptoUtilsException;
import cinvestav.android.pki.cryptography.utils.CryptoUtils;

/**
 * @author Ing. Javier Silva Pérez - [javier]
 * 
 */
public class RSAPrivateKey {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	private BigInteger version;
	private BigInteger modulus;
	private BigInteger publicExponent;
	private BigInteger privateExponent;
	private BigInteger primeP;
	private BigInteger primeQ;
	private BigInteger dP;
	private BigInteger dQ;
	private BigInteger coefficient;

	/*
	 * { "AES-128-CBC", "AES-128-CFB", "AES-128-ECB", "AES-128-OFB",
	 * "AES-192-CBC", "AES-192-CFB", "AES-192-ECB", "AES-192-OFB",
	 * "AES-256-CBC", "AES-256-CFB", "AES-256-ECB", "AES-256-OFB", "BF-CBC",
	 * "BF-CFB", "BF-ECB", "BF-OFB", "DES-CBC", "DES-CFB", "DES-ECB", "DES-OFB",
	 * "DES-EDE", "DES-EDE-CBC", "DES-EDE-CFB", "DES-EDE-ECB", "DES-EDE-OFB",
	 * "DES-EDE3", "DES-EDE3-CBC", "DES-EDE3-CFB", "DES-EDE3-ECB",
	 * "DES-EDE3-OFB", "RC2-CBC", "RC2-CFB", "RC2-ECB", "RC2-OFB", "RC2-40-CBC",
	 * "RC2-64-CBC" };
	 */

	/**
	 * Default constructor, inits all elements in 0
	 */
	public RSAPrivateKey() {
		super();
		this.version = new BigInteger("0");
		this.modulus = new BigInteger("0");
		this.publicExponent = new BigInteger("0");
		this.privateExponent = new BigInteger("0");
		this.primeP = new BigInteger("0");
		this.primeQ = new BigInteger("0");
		this.dP = new BigInteger("0");
		this.dQ = new BigInteger("0");
		this.coefficient = new BigInteger("0");
	}

	/**
	 * Copy constructor
	 * 
	 * @param rsaPrivateKey
	 *            Source PrivateKey
	 */
	public RSAPrivateKey(RSAPrivateKey rsaPrivateKey) {
		super();
		this.version = rsaPrivateKey.version;
		this.modulus = rsaPrivateKey.modulus;
		this.publicExponent = rsaPrivateKey.publicExponent;
		this.primeP = rsaPrivateKey.primeP;
		this.primeQ = rsaPrivateKey.primeQ;
		this.privateExponent = rsaPrivateKey.privateExponent;
		this.dP = rsaPrivateKey.dP;
		this.dQ = rsaPrivateKey.dQ;
		this.coefficient = rsaPrivateKey.coefficient;
	}

	/**
	 * Parameterized constructor
	 * 
	 * @param version
	 * @param modulus
	 * @param publicExponent
	 * @param privateExponent
	 * @param primeP
	 * @param primeP
	 * @param dP
	 * @param dQ
	 * @param coefficient
	 */
	public RSAPrivateKey(BigInteger version, BigInteger modulus,
			BigInteger publicExponent, BigInteger privateExponent,
			BigInteger primeP, BigInteger primeQ, BigInteger dP, BigInteger dQ,
			BigInteger coefficient) {
		super();
		this.version = version;
		this.modulus = modulus;
		this.publicExponent = publicExponent;
		this.privateExponent = privateExponent;
		this.primeP = primeP;
		this.primeQ = primeQ;
		this.dP = dP;
		this.dQ = dQ;
		this.coefficient = coefficient;
	}

	public BigInteger getVersion() {
		return version;
	}

	public void setVersion(BigInteger version) {
		this.version = version;
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

	public BigInteger getPrivateExponent() {
		return privateExponent;
	}

	public void setPrivateExponent(BigInteger privateExponent) {
		this.privateExponent = privateExponent;
	}

	public BigInteger getPrime1() {
		return primeP;
	}

	public void setPrime1(BigInteger prime1) {
		this.primeP = prime1;
	}

	public BigInteger getPrime2() {
		return primeQ;
	}

	public void setPrime2(BigInteger prime2) {
		this.primeQ = prime2;
	}

	public BigInteger getExponent1() {
		return dP;
	}

	public void setExponent1(BigInteger exponent1) {
		this.dP = exponent1;
	}

	public BigInteger getExponent2() {
		return dQ;
	}

	public void setExponent2(BigInteger exponent2) {
		this.dQ = exponent2;
	}

	public BigInteger getCoefficient() {
		return coefficient;
	}

	public void setCoefficient(BigInteger coefficient) {
		this.coefficient = coefficient;
	}

	@Override
	public String toString() {
		return "RSAPrivateKey [version=" + version + ", modulus=" + modulus
				+ ", publicExponent=" + publicExponent + ", privateExponent="
				+ privateExponent + ", primeP=" + primeP + ", primeQ=" + primeQ
				+ ", dP=" + dP + ", dQ=" + dQ + ", coefficient=" + coefficient
				+ "]";
	}

	/**
	 * ToString method using a specific encoder
	 * 
	 * @param encoder
	 *            see available encoders in
	 *            {@link cinvestav.android.pki.cryptography.utils.CryptoUtils}
	 * @return String Private Key encoded
	 */
	public String toString(String encoder) {
		if (encoder.equalsIgnoreCase(CryptoUtils.ENCODER_BASE64)) {
			return "RSAPrivateKey [version="
					+ new String(Base64.encode(version.toByteArray()))
					+ ", modulus="
					+ new String(Base64.encode(modulus.toByteArray()))
					+ ", publicExponent="
					+ new String(Base64.encode(publicExponent.toByteArray()))
					+ ", privateExponent="
					+ new String(Base64.encode(privateExponent.toByteArray()))
					+ ", primeP="
					+ new String(Base64.encode(primeP.toByteArray()))
					+ ", primeQ="
					+ new String(Base64.encode(primeQ.toByteArray())) + ", dP="
					+ new String(Base64.encode(dP.toByteArray())) + ", dQ="
					+ new String(Base64.encode(dQ.toByteArray()))
					+ ", coefficient="
					+ new String(Base64.encode(coefficient.toByteArray()))
					+ "]";

		}
		if (encoder.equalsIgnoreCase(CryptoUtils.ENCODER_HEX)) {
			return "RSAPrivateKey [version="
					+ new String(Hex.encode(version.toByteArray()))
					+ ", modulus="
					+ new String(Hex.encode(modulus.toByteArray()))
					+ ", publicExponent="
					+ new String(Hex.encode(publicExponent.toByteArray()))
					+ ", privateExponent="
					+ new String(Hex.encode(privateExponent.toByteArray()))
					+ ", primeP="
					+ new String(Hex.encode(primeP.toByteArray()))
					+ ", primeQ="
					+ new String(Hex.encode(primeQ.toByteArray())) + ", dP="
					+ new String(Hex.encode(dP.toByteArray())) + ", dQ="
					+ new String(Hex.encode(dQ.toByteArray()))
					+ ", coefficient="
					+ new String(Hex.encode(coefficient.toByteArray())) + "]";
		}
		return "RSAPrivateKey [version=" + version + ", modulus=" + modulus
				+ ", publicExponent=" + publicExponent + ", privateExponent="
				+ privateExponent + ", primeP=" + primeP + ", primeQ=" + primeQ
				+ ", dP=" + dP + ", dQ=" + dQ + ", coefficient=" + coefficient
				+ "]";
	}

	@Override
	public boolean equals(Object obj) {
		if (obj instanceof RSAPrivateKey) {
			RSAPrivateKey key = (RSAPrivateKey) obj;
			boolean res = key.coefficient.equals(this.coefficient)
					&& key.dP.equals(this.dP) && key.dQ.equals(this.dQ)
					&& key.modulus.equals(this.modulus)
					&& key.primeP.equals(this.primeP)
					&& key.primeQ.equals(this.primeQ)
					&& key.privateExponent.equals(this.privateExponent)
					&& key.publicExponent.equals(this.publicExponent);
			// && key.version.equals(this.version);
			return res;
		} else {
			return false;
		}
	}

	private Cipher getCipher(boolean encrypt, Provider provider,
			char[] password, String dekAlgName, byte[] iv)
			throws CryptoUtilsException {
		AlgorithmParameterSpec paramSpec = new IvParameterSpec(iv);
		String alg;
		String blockMode = "CBC";
		String padding = "PKCS5Padding";
		Key sKey;

		// Figure out block mode and padding.
		if (dekAlgName.endsWith("-CFB")) {
			blockMode = "CFB";
			padding = "NoPadding";
		}
		if (dekAlgName.endsWith("-ECB") || "DES-EDE".equals(dekAlgName)
				|| "DES-EDE3".equals(dekAlgName)) {
			// ECB is actually the default (though seldom used) when OpenSSL
			// uses DES-EDE (des2) or DES-EDE3 (des3).
			blockMode = "ECB";
			paramSpec = null;
		}
		if (dekAlgName.endsWith("-OFB")) {
			blockMode = "OFB";
			padding = "NoPadding";
		}

		// Figure out algorithm and key size.
		if (dekAlgName.startsWith("DES-EDE")) {
			alg = "DESede";
			// "DES-EDE" is actually des2 in OpenSSL-speak!
			// "DES-EDE3" is des3.
			boolean des2 = !dekAlgName.startsWith("DES-EDE3");
			sKey = getKey(password, alg, 24, iv, des2);
		} else if (dekAlgName.startsWith("DES-")) {
			alg = "DES";
			sKey = getKey(password, alg, 8, iv);
		} else if (dekAlgName.startsWith("BF-")) {
			alg = "Blowfish";
			sKey = getKey(password, alg, 16, iv);
		} else if (dekAlgName.startsWith("RC2-")) {
			alg = "RC2";
			int keyBits = 128;
			if (dekAlgName.startsWith("RC2-40-")) {
				keyBits = 40;
			} else if (dekAlgName.startsWith("RC2-64-")) {
				keyBits = 64;
			}
			sKey = getKey(password, alg, keyBits / 8, iv);
			if (paramSpec == null) // ECB block mode
			{
				paramSpec = new RC2ParameterSpec(keyBits);
			} else {
				paramSpec = new RC2ParameterSpec(keyBits, iv);
			}
		} else if (dekAlgName.startsWith("AES-")) {
			alg = "AES";
			byte[] salt = iv;
			if (salt.length > 8) {
				salt = new byte[8];
				System.arraycopy(iv, 0, salt, 0, 8);
			}

			int keyBits;
			if (dekAlgName.startsWith("AES-128-")) {
				keyBits = 128;
			} else if (dekAlgName.startsWith("AES-192-")) {
				keyBits = 192;
			} else if (dekAlgName.startsWith("AES-256-")) {
				keyBits = 256;
			} else {
				throw new CryptoUtilsException(
						"unknown AES encryption with private key");
			}
			sKey = getKey(password, "AES", keyBits / 8, salt);
		} else {
			throw new CryptoUtilsException(
					"unknown encryption with private key");
		}

		String transformation = alg + "/" + blockMode + "/" + padding;

		try {
			Cipher c = Cipher.getInstance(transformation, provider);
			int mode = encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE;

			if (paramSpec == null) // ECB block mode
			{
				c.init(mode, sKey);
			} else {
				c.init(mode, sKey, paramSpec);
			}
			return c;
		} catch (Exception e) {
			throw new CryptoUtilsException(
					"exception using cipher - please check password and data.",
					e);
		}
	}

	private SecretKey getKey(char[] password, String algorithm, int keyLength,
			byte[] salt) {
		return getKey(password, algorithm, keyLength, salt, false);
	}

	private SecretKey getKey(char[] password, String algorithm, int keyLength,
			byte[] salt, boolean des2) {
		OpenSSLPBEParametersGenerator pGen = new OpenSSLPBEParametersGenerator();

		pGen.init(PBEParametersGenerator.PKCS5PasswordToBytes(password), salt);

		KeyParameter keyParam;
		keyParam = (KeyParameter) pGen.generateDerivedParameters(keyLength * 8);
		byte[] key = keyParam.getKey();
		if (des2 && key.length >= 24) {
			// For DES2, we must copy first 8 bytes into the last 8 bytes.
			System.arraycopy(key, 0, key, 16, 8);
		}
		return new javax.crypto.spec.SecretKeySpec(key, algorithm);
	}

	/**
	 * Parse a {@link org.spongycastle.crypto.params.RSAPrivateCrtKeyParameters}
	 * and stores the result in the current object
	 * 
	 * @param privateKey
	 *            RSAPrivateCrtKeyParameters object
	 */
	public static RSAPrivateKey parse(RSAPrivateCrtKeyParameters privateKey) {
		return new RSAPrivateKey(BigInteger.ONE, privateKey.getModulus(),
				privateKey.getPublicExponent(), privateKey.getExponent(),
				privateKey.getP(), privateKey.getQ(), privateKey.getDP(),
				privateKey.getDQ(), privateKey.getQInv());
	}

	/**
	 * Generic parser, saves the result in this object
	 * 
	 * @param privateKey
	 *            Private key object, supported object types are:
	 *            {@link org.spongycastle.crypto.params.RSAPrivateCrtKeyParameters}
	 *            , {@link org.spongycastle.asn1.pkcs.RSAPrivateKey},
	 *            {@link java.security.interfaces.RSAPrivateCrtKey}
	 * @throws CryptoUtilsException
	 */
	public static RSAPrivateKey parse(Object privateKey)
			throws CryptoUtilsException {
		if (privateKey instanceof RSAPrivateCrtKeyParameters) {
			return parse((RSAPrivateCrtKeyParameters) privateKey);
		} else if (privateKey instanceof org.spongycastle.asn1.pkcs.RSAPrivateKey) {
			return parse((org.spongycastle.asn1.pkcs.RSAPrivateKey) privateKey);
		} else if (privateKey instanceof java.security.interfaces.RSAPrivateCrtKey) {
			return parse((java.security.interfaces.RSAPrivateCrtKey) privateKey);
		} else {
			throw new CryptoUtilsException(
					"Parse error: Private key object type not supported");
		}
	}

	/**
	 * Parse an {@link org.spongycastle.asn1.pkcs.RSAPrivateKey} object(in pkcs
	 * format) to RSAPrivateKey and stores the result in the invoking object
	 * 
	 * @param privateKey
	 *            RSA Private key to be parsed (
	 *            {@link org.spongycastle.asn1.pkcs.RSAPrivateKey})
	 */
	public static RSAPrivateKey parse(
			org.spongycastle.asn1.pkcs.RSAPrivateKey privateKey) {
		return new RSAPrivateKey(privateKey.getVersion(),
				privateKey.getModulus(), privateKey.getPublicExponent(),
				privateKey.getPrivateExponent(), privateKey.getPrime1(),
				privateKey.getPrime2(), privateKey.getExponent1(),
				privateKey.getExponent2(), privateKey.getCoefficient());
	}

	/**
	 * Parse an {@link java.security.interfaces.RSAPrivateCrtKey} object to
	 * RSAPrivateKey and stores the result in the invoking object
	 * 
	 * @param privateKey
	 *            Java default RSA Private Key object
	 */
	public static RSAPrivateKey parse(
			java.security.interfaces.RSAPrivateCrtKey privateKey) {
		return new RSAPrivateKey(BigInteger.ONE, privateKey.getModulus(),
				privateKey.getPublicExponent(),
				privateKey.getPrivateExponent(), privateKey.getPrimeP(),
				privateKey.getPrimeQ(), privateKey.getPrimeExponentP(),
				privateKey.getPrimeExponentQ(), privateKey.getCrtCoefficient());
	}

	/**
	 * Parse the current object to
	 * {@link org.spongycastle.crypto.params.RSAPrivateCrtKeyParameters}
	 * 
	 * @return RSAPrivateCrtKeyParameters object
	 */
	public RSAPrivateCrtKeyParameters parseToRSAPrivateCrtKeyParameters() {
		RSAPrivateCrtKeyParameters privateKey = new RSAPrivateCrtKeyParameters(
				this.modulus, this.publicExponent, this.privateExponent,
				this.primeP, this.primeQ, this.dP, this.dQ, this.coefficient);
		return privateKey;
	}

	/**
	 * Parse the current object to
	 * {@link org.spongycastle.asn1.pkcs.RSAPrivateKey} (in PKCS format)
	 * 
	 * @return RSAPrivateKey in PKCS format
	 */
	public org.spongycastle.asn1.pkcs.RSAPrivateKey parseToRSAPrivateKey() {
		return new org.spongycastle.asn1.pkcs.RSAPrivateKey(this.modulus,
				this.publicExponent, this.privateExponent, this.primeP,
				this.primeQ, this.dP, this.dQ, this.coefficient);
	}

	/**
	 * Parse the current object to
	 * {@link java.security.interfaces.RSAPrivateCrtKey}
	 * 
	 * @return RSAPrivateKey object compatible with JCE
	 * @throws CryptoUtilsException
	 */
	public java.security.interfaces.RSAPrivateCrtKey parseToJCERSAPrivateCrtKey()
			throws CryptoUtilsException {
		RSAPrivateCrtKeySpec privSpec = new RSAPrivateCrtKeySpec(this.modulus,
				publicExponent, privateExponent, primeP, primeQ, dP, dQ,
				coefficient);

		KeyFactory keyFact;
		try {
			keyFact = KeyFactory.getInstance("RSA", CryptoUtils.PROVIDER);
			return (java.security.interfaces.RSAPrivateCrtKey) keyFact
					.generatePrivate(privSpec);
		} catch (NoSuchAlgorithmException e) {
			throw new CryptoUtilsException("Parse to JCE RSAPublicKey error: "
					+ e, e);
		} catch (NoSuchProviderException e) {
			throw new CryptoUtilsException("Parse to JCE RSAPublicKey error: "
					+ e, e);
		} catch (InvalidKeySpecException e) {
			throw new CryptoUtilsException("Parse to JCE RSAPublicKey error: "
					+ e, e);
		}
	}

	/**
	 * Save this RSAPrivateKey to a file using encrypted PKCS8 PEM format
	 * 
	 * @param filePath
	 *            File Full path in which the key will be stored
	 * @param algorithm
	 *            Algorithm to be use for encrypt the file
	 * @param password
	 *            Encryption password
	 * @throws CryptoUtilsException
	 */
	public void savePKCS8PEM(String filePath, String algorithm, String password)
			throws CryptoUtilsException {
		try {
			File file = new File(filePath);
			// File file2 = new File(filePath+"2");
			if (!file.exists()) {
				file.createNewFile();
			}

			PEMWriter pWrt = new PEMWriter(new FileWriter(file),
					CryptoUtils.PROVIDER);

			PKCS8Generator pkcs8;

			// pkcs8 = new PKCS8Generator(this.parseToJCERSAPrivateCrtKey(),
			// selectAlgorithmID(algorithm, "PEM"),
			// AndroidCryptoUtils.PROVIDER);

			pkcs8 = new PKCS8Generator(this.parseToJCERSAPrivateCrtKey(),
					CryptoUtils.selectAlgorithmID(algorithm, "PEM"),
					CryptoUtils.PROVIDER);

			pkcs8.setPassword(password.toCharArray());

			// pWrt.writeObject(parseToJCERSAPrivateCrtKey(), algorithm,
			// password.toCharArray(), AndroidCryptoUtils.secureRandom);

			pWrt.writeObject(pkcs8);

			pWrt.close();

		} catch (NoSuchProviderException e) {

			throw new CryptoUtilsException(
					"Save RSA Private Key as PKCS8 PEM file error: " + e, e);
		} catch (NoSuchAlgorithmException e) {

			throw new CryptoUtilsException(
					"Save RSA Private Key as PKCS8 PEM file error: " + e, e);
		} catch (IOException e) {

			throw new CryptoUtilsException(
					"Save RSA Private Key as PKCS8 PEM file error: " + e, e);
		}
	}

	/**
	 * Save this RSAPrivateKey to a file using plain PKCS8 PEM format
	 * 
	 * @param filePath
	 *            File in with the key will be stored
	 * @throws CryptoUtilsException
	 */
	public void savePKCS8PEM(String filePath) throws CryptoUtilsException {
		try {
			File file = new File(filePath);
			if (!file.exists()) {
				file.createNewFile();
			}

			PEMWriter pWrt = new PEMWriter(new FileWriter(file),
					CryptoUtils.PROVIDER);

			PKCS8Generator pkcs8;

			pkcs8 = new PKCS8Generator(this.parseToJCERSAPrivateCrtKey());

			pWrt.writeObject(pkcs8);

			pWrt.close();

		} catch (IOException e) {

			throw new CryptoUtilsException(
					"Save RSA Private Key as PKCS8 PEM file error: " + e, e);
		}
	}

	/**
	 * Save the RSA Private key in PKCS8 format using DER encoding
	 * 
	 * @param privateKeyfullPath
	 *            Full path with file name in which the key will be saved
	 * @throws CryptoUtilsException
	 */
	public void savePKCS8DER(String privateKeyfullPath, String algorithm,
			String password) throws CryptoUtilsException {

		byte[] keyBytes;
		try {
			keyBytes = this.parseToRSAPrivateKey().toASN1Primitive()
					.getEncoded("DER");

			String dekAlgName = Strings.toUpperCase(algorithm);

			// Note: For backward compatibility
			if (dekAlgName.equals("DESEDE")) {
				dekAlgName = "DES-EDE3-CBC";
			}

			int ivLength = dekAlgName.startsWith("AES-") ? 16 : 8;

			byte[] iv = new byte[ivLength];
			CryptoUtils.secureRandom.nextBytes(iv);
			Cipher c = getCipher(true,
					Security.getProvider(CryptoUtils.PROVIDER),
					password.toCharArray(), dekAlgName, iv);
			byte[] encData = c.doFinal(keyBytes);

			/*
			 * byte[] salt = new byte[8];
			 * AndroidCryptoUtils.secureRandom.nextBytes(salt); String
			 * derAlgorithm = selectAlgorithmID(algorithm, "DER"); // Create PBE
			 * parameter set PBEParameterSpec pbeParamSpec = new
			 * PBEParameterSpec(salt, count); PBEKeySpec pbeKeySpec = new
			 * PBEKeySpec(password.toCharArray()); SecretKeyFactory keyFac =
			 * SecretKeyFactory.getInstance(derAlgorithm); SecretKey pbeKey =
			 * keyFac.generateSecret(pbeKeySpec);
			 * 
			 * Cipher pbeCipher =
			 * Cipher.getInstance(derAlgorithm,AndroidCryptoUtils.PROVIDER);
			 * 
			 * // Initialize PBE Cipher with key and parameters
			 * pbeCipher.init(Cipher.ENCRYPT_MODE, pbeKey, pbeParamSpec);
			 * 
			 * // Encrypt the encoded Private Key with the PBE key byte[]
			 * ciphertext = pbeCipher.doFinal(keyBytes);
			 */

			// Now construct PKCS #8 EncryptedPrivateKeyInfo object
			/*
			 * AlgorithmParameterSpec paramSpec = new IvParameterSpec(iv);
			 * AlgorithmParameters algparms = AlgorithmParameters.getInstance(
			 * selectAlgorithmID(dekAlgName, "DER"),
			 * AndroidCryptoUtils.PROVIDER); algparms.init(paramSpec);
			 */
			// AlgorithmIdentifier algId;
			AlgorithmParameters algparms = c.getParameters();

			EncryptedPrivateKeyInfo encinfo = new EncryptedPrivateKeyInfo(
					algparms, encData);

			// and here we have it! a DER encoded PKCS#8 encrypted key!
			byte[] encryptedPkcs8 = encinfo.getEncoded();

			File file = new File(privateKeyfullPath);
			FileOutputStream fos = new FileOutputStream(file);
			fos.write(encryptedPkcs8);
			fos.flush();
			fos.close();
		} catch (FileNotFoundException e) {

			throw new CryptoUtilsException(
					"Save RSA Private Key as PKCS8 DER file error: " + e, e);
		} catch (IOException e) {

			throw new CryptoUtilsException(
					"Save RSA Private Key as PKCS8 DER file error: " + e, e);
		} catch (NoSuchAlgorithmException e) {

			e.printStackTrace();
			throw new CryptoUtilsException(
					"Save RSA Private Key as PKCS8 DER file error: " + e, e);

		} catch (IllegalBlockSizeException e) {

			e.printStackTrace();
		} catch (BadPaddingException e) {

			e.printStackTrace();
		}
	}

	/**
	 * Save the RSA Private key in Plain PKCS8 format using DER encoding
	 * 
	 * @param privateKeyfullPath
	 *            Full path with file name in which the key will be saved
	 * @throws CryptoUtilsException
	 */
	public void savePKCS8DER(String privateKeyfullPath)
			throws CryptoUtilsException {

		byte[] keyBytes;
		try {
			keyBytes = this.parseToRSAPrivateKey().toASN1Primitive()
					.getEncoded("DER");

			File file = new File(privateKeyfullPath);
			FileOutputStream fos = new FileOutputStream(file);
			fos.write(keyBytes);
			fos.flush();
			fos.close();
		} catch (FileNotFoundException e) {

			throw new CryptoUtilsException(
					"Save RSA Private Key as Plain PKCS8 DER file error: " + e,
					e);
		} catch (IOException e) {

			throw new CryptoUtilsException(
					"Save RSA Private Key as Plain PKCS8 DER file error: " + e,
					e);
		}
	}

	/**
	 * Load the private key from Encrypted PKCS8 DER encoded file
	 * 
	 * @param publicKeyFullPath
	 *            Path of the private key
	 * @param password
	 *            Password used to encrypt the key
	 * @return Private key read from the file
	 * @throws CryptoUtilsException
	 */
	public static RSAPrivateKey loadPKCS8DER(String privateKeyFullPath,
			String password) throws CryptoUtilsException {

		File f = new File(privateKeyFullPath);
		if (!f.exists()) {
			throw new CryptoUtilsException(
					"Load RSA Private Key from PKCS8 file error: File ["
							+ privateKeyFullPath + "] not found");
		}

		// Read file bytes
		FileInputStream fis;
		try {
			fis = new FileInputStream(f);

			DataInputStream dis = new DataInputStream(fis);
			byte[] keyBytes = new byte[(int) f.length()];
			dis.readFully(keyBytes);
			dis.close();

			EncryptedPrivateKeyInfo encryptPKInfo = new EncryptedPrivateKeyInfo(
					keyBytes);
			AlgorithmParameters algParams = encryptPKInfo.getAlgParameters();

			Cipher cipher = Cipher.getInstance(encryptPKInfo.getAlgName(),
					CryptoUtils.PROVIDER);

			PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
			SecretKeyFactory secFac = SecretKeyFactory.getInstance(
					encryptPKInfo.getAlgName(), CryptoUtils.PROVIDER);
			Key pbeKey = secFac.generateSecret(pbeKeySpec);

			cipher.init(Cipher.DECRYPT_MODE, pbeKey, algParams);

			/*
			 * Cipher c = crypt(false,
			 * Security.getProvider(AndroidCryptoUtils.PROVIDER), keyBytes,
			 * password.toCharArray(), dekAlgName, iv);
			 */

			KeySpec pkcs8KeySpec = encryptPKInfo.getKeySpec(cipher);
			KeyFactory kf = KeyFactory.getInstance("RSA", CryptoUtils.PROVIDER);
			return parse(kf.generatePrivate(pkcs8KeySpec));

		} catch (FileNotFoundException e) {

			throw new CryptoUtilsException(
					"Load RSA Private Key from PKCS8 DER file error: " + e, e);
		} catch (IOException e) {

			throw new CryptoUtilsException(
					"Load RSA Private Key from PKCS8 DER file error: " + e, e);
		} catch (NoSuchAlgorithmException e) {

			throw new CryptoUtilsException(
					"Load RSA Private Key from PKCS8 DER file error: " + e, e);
		} catch (NoSuchPaddingException e) {

			throw new CryptoUtilsException(
					"Load RSA Private Key from PKCS8 DER file error: " + e, e);
		} catch (InvalidKeySpecException e) {

			throw new CryptoUtilsException(
					"Load RSA Private Key from PKCS8 DER file error: " + e, e);
		} catch (InvalidKeyException e) {

			throw new CryptoUtilsException(
					"Load RSA Private Key from PKCS8 DER file error: " + e, e);
		} catch (InvalidAlgorithmParameterException e) {

			throw new CryptoUtilsException(
					"Load RSA Private Key from PKCS8 DER file error: " + e, e);
		} catch (NoSuchProviderException e) {

			throw new CryptoUtilsException(
					"Load RSA Private Key from PKCS8 DER file error: " + e, e);
		} catch (IllegalArgumentException e) {
			throw new CryptoUtilsException(
					"Load RSA Private Key from DER file error: " + e, e);
		}

	}

	/**
	 * Load the private key from Plain PKCS8 DER encoded file
	 * 
	 * @param publicKeyFullPath
	 *            Path of the private key
	 * @return Private key read from the file
	 * @throws CryptoUtilsException
	 */
	public static RSAPrivateKey loadPKCS8DER(String privateKeyFullPath)
			throws CryptoUtilsException {
		try {
			File file = new File(privateKeyFullPath);
			if (file.exists()) {
				FileInputStream fis;

				fis = new FileInputStream(file);

				byte[] key = new byte[(int) file.length()];
				fis.read(key);
				fis.close();

				return parse(org.spongycastle.asn1.pkcs.RSAPrivateKey
						.getInstance(key));

			} else {
				throw new CryptoUtilsException(
						"RSA Private Key file not found :" + privateKeyFullPath);
			}
		} catch (FileNotFoundException e) {
			throw new CryptoUtilsException(
					"Load RSA Private Key from PKCS8 DER file error: " + e, e);
		} catch (IOException e) {
			throw new CryptoUtilsException(
					"Load RSA Private Key from PKCS8 DER file error: " + e, e);
		} catch (IllegalArgumentException e) {
			throw new CryptoUtilsException(
					"Load RSA Private Key from PKCS8 DER file error: " + e, e);
		}
	}

	/**
	 * Read an Encrypted RSA Private Key from the specified file
	 * 
	 * @param filePath
	 *            File that contains the RSA Private Key
	 * @param password
	 *            Password of the encrypted file
	 * @throws CryptoUtilsException
	 */
	public static RSAPrivateKey loadPKCS8PEM(String filePath, String password)
			throws CryptoUtilsException {

		File file = new File(filePath);
		if (!file.exists()) {
			throw new CryptoUtilsException(
					"Load RSA Private Key from PKCS8 PEM file error: File ["
							+ filePath + "] not found");
		}

		InputStream ins;
		try {
			ins = new FileInputStream(file);

			InputStreamReader isr = new InputStreamReader(ins);

			DefaultPasswordFinder pass = new DefaultPasswordFinder(
					password.toCharArray());

			PEMReader pRd = new PEMReader(isr, pass);

			Object keyObj = pRd.readObject();

			pRd.close();
			return parse(keyObj);
		} catch (FileNotFoundException e) {

			throw new CryptoUtilsException(
					"Load RSA Private Key from PKCS8 PEM file error: " + e, e);
		} catch (IOException e) {

			throw new CryptoUtilsException(
					"Load RSA Private Key from PKCS8 PEM file error: " + e, e);
		}
	}

	/**
	 * Read an Encrypted RSA Private Key from the specified file
	 * 
	 * @param filePath
	 * @throws CryptoUtilsException
	 */
	public static RSAPrivateKey loadPKCS8PEM(String filePath)
			throws CryptoUtilsException {
		File file = new File(filePath);
		if (!file.exists()) {
			throw new CryptoUtilsException(
					"Load RSA Private Key from PKCS8 PEM file error: File ["
							+ filePath + "] not found");
		}

		InputStream ins;
		try {
			ins = new FileInputStream(file);

			InputStreamReader isr = new InputStreamReader(ins);

			PEMReader pRd = new PEMReader(isr);

			Object keyObj = pRd.readObject();

			pRd.close();
			return parse(keyObj);
		} catch (FileNotFoundException e) {

			throw new CryptoUtilsException(
					"Load RSA Private Key from PKCS8 PEM file error: " + e, e);
		} catch (IOException e) {

			throw new CryptoUtilsException(
					"Load RSA Private Key from PKCS8 PEM file error: " + e, e);
		}
	}

	/**
	 * Encodes this RSAPrivateKey object as a base64 encoded byte array using
	 * PEM with password protection
	 * 
	 * @param password
	 *            Password to protect the key
	 * 
	 * @throws CryptoUtilsException
	 */
	public byte[] encode(String password) throws CryptoUtilsException {
		try {
			StringWriter wrt = new StringWriter();
			PEMWriter pWrt = new PEMWriter(wrt, CryptoUtils.PROVIDER);

			PKCS8Generator pkcs8;

			pkcs8 = new PKCS8Generator(this.parseToJCERSAPrivateCrtKey(),
					CryptoUtils.selectAlgorithmID(CryptoUtils.AES_256_CBC,
							"PEM"), CryptoUtils.PROVIDER);

			pkcs8.setPassword(password.toCharArray());

			pWrt.writeObject(pkcs8);
			pWrt.close();

			return Base64.encode(wrt.toString().getBytes());

		} catch (NoSuchProviderException e) {
			throw new CryptoUtilsException(
					"Encode RSA Private Key error: " + e, e);
		} catch (NoSuchAlgorithmException e) {
			throw new CryptoUtilsException(
					"Encode RSA Private Key error: " + e, e);
		} catch (IOException e) {
			throw new CryptoUtilsException(
					"Encode RSA Private Key error: " + e, e);
		}
	}

	/**
	 * Decodes a byte array encoded using base64 to an RSAPrivateKey object
	 * 
	 * @param keyBytes
	 *            Base64 encoded byte array representing the key
	 * @param password
	 *            Password used for encoding the key
	 * @return A new RSAPrivateKey that correspond to the encoded bytes
	 * @throws CryptoUtilsException
	 *             if the byte array does not correspond to a Base64
	 *             RSAPrivateKey encoded key
	 */
	public static RSAPrivateKey decode(byte[] keyBytes, String password)
			throws CryptoUtilsException {

		try {
			InputStream ins = new ByteArrayInputStream(Base64.decode(keyBytes));

			InputStreamReader isr = new InputStreamReader(ins);

			DefaultPasswordFinder pass = new DefaultPasswordFinder(
					password.toCharArray());

			PEMReader pRd = new PEMReader(isr, pass);

			Object keyObj = pRd.readObject();

			pRd.close();
			return parse(keyObj);

		} catch (IOException e) {
			throw new CryptoUtilsException(
					"Decode RSA Private Key error: " + e, e);
		}
	}

}
