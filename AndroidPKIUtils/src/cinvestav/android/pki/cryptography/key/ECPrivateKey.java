/**
 *  Created on  : 06/06/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	Wraps the information of a Elliptic Curve Private Key and contain some parse functions 
 *  	to interact with JCE and SpongyCastle EC privateKey representations
 */
package cinvestav.android.pki.cryptography.key;

import java.io.ByteArrayInputStream;
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
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import org.spongycastle.crypto.params.ECPrivateKeyParameters;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.jce.provider.JCEECPrivateKey;
import org.spongycastle.openssl.PEMReader;
import org.spongycastle.openssl.PEMWriter;
import org.spongycastle.openssl.PKCS8Generator;
import org.spongycastle.util.encoders.Base64;
import org.spongycastle.util.encoders.Hex;

import cinvestav.android.pki.cryptography.ec.ECDomainParameters;
import cinvestav.android.pki.cryptography.exception.CryptoUtilsException;
import cinvestav.android.pki.cryptography.utils.CryptoUtils;

/**
 * Wraps the information of a Elliptic Curve Private Key and contain some parse
 * functions to interact with JCE and SpongyCastle EC privateKey representations
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 06/06/2012
 * @version 1.0
 */
public class ECPrivateKey {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	private ECDomainParameters params;
	private BigInteger d;

	/**
	 * Copy constructor
	 * 
	 * @param privateKey
	 *            Source privateKey
	 */
	public ECPrivateKey(ECPrivateKey privateKey) {
		this.params = privateKey.getParams();
		this.d = privateKey.getD();
	}

	/**
	 * Default parameterized constructor
	 * 
	 * @param params
	 *            Parameters of the curve
	 * @param d
	 *            BigInteger that represents the privateKey
	 */
	public ECPrivateKey(ECDomainParameters params, BigInteger d) {
		super();
		this.params = params;
		this.d = d;
	}

	public ECDomainParameters getParams() {
		return params;
	}

	public void setParams(ECDomainParameters params) {
		this.params = params;
	}

	public BigInteger getD() {
		return d;
	}

	public void setD(BigInteger d) {
		this.d = d;
	}

	@Override
	public String toString() {
		return "ECPrivateKey [params=" + params + ", d=" + d + "]";
	}

	/**
	 * ToString method using a specific encoder
	 * 
	 * @param encoder
	 *            see available encoders in
	 *            {@link cinvestav.android.pki.cryptography.utils.CryptoUtils}
	 * @return String EC Private Key encoded
	 */
	public String toString(String encoder) {
		if (encoder.equalsIgnoreCase(CryptoUtils.ENCODER_BASE64)) {
			return "ECPrivateKey [params=" + params.toString(encoder) + ", d="
					+ new String(Base64.encode(d.toByteArray())) + "]";
		}
		if (encoder.equalsIgnoreCase(CryptoUtils.ENCODER_HEX)) {
			return "ECPrivateKey [params=" + params.toString(encoder) + ", d="
					+ new String(Hex.encode(d.toByteArray())) + "]";
		}
		return "ECPrivateKey [params=" + params + ", d=" + d + "]";
	}

	@Override
	public boolean equals(Object obj) {
		if (obj instanceof ECPrivateKey) {
			ECPrivateKey key = (ECPrivateKey) obj;
			boolean res = key.d.equals(this.d)
					&& key.params.equals(this.params);
			return res;
		} else {
			return false;
		}
	}

	/**
	 * Parse an object of type ECPrivateKeyParameters (
	 * {@link org.spongycastle.crypto.params.ECPrivateKeyParameter}) to this
	 * class
	 * 
	 * @param privateKey
	 *            ECPrivateKeyParameters Private key object
	 * @return A new ECPrivateKey object with the parsed values;
	 * @throws CryptoUtilsException
	 */
	public static ECPrivateKey parse(ECPrivateKeyParameters privateKey)
			throws CryptoUtilsException {
		ECPrivateKey privateKeyRes = new ECPrivateKey(
				ECDomainParameters.parse(privateKey.getParameters()),
				privateKey.getD());
		return privateKeyRes;
	}

	/**
	 * Parse the calling object to ECPrivateKeyParameters type (
	 * {@link org.spongycastle.crypto.params.ECPrivateKeyParameter})
	 * 
	 * @return A ECPrivateKeyParameters with the values of the calling object
	 */
	public ECPrivateKeyParameters parseToECPrivateKeyParameters() {
		ECPrivateKeyParameters privateKey = new ECPrivateKeyParameters(this.d,
				params.parseToECDomainParameters());
		return privateKey;
	}

	/**
	 * Parse a JCE ECPrivateKey {@link java.security.interfaces.ECPrivateKey})
	 * to this class, the result will be in the calling object
	 * 
	 * @param privateKey
	 *            JCE ECPrivateKey object
	 * @throws CryptoUtilsException
	 */
	/*
	 * public void parse(java.security.interfaces.ECPrivateKey privateKey)
	 * throws CryptoUtilsException { this.d = privateKey.getS(); this.params =
	 * ECDomainParameters.parse(privateKey.getParams()); }
	 * 
	 * public java.security.interfaces.ECPrivateKey parseToJCEECPrivateKey(){
	 * java.security.interfaces.ECPrivateKey privateKey = new
	 * java.security.interfaces.ECPrivateKey }
	 */

	/**
	 * Parse the JCE ECPrivateKeySpec (
	 * {@link java.security.spec.ECPrivateKeySpec})
	 * 
	 * @param privateKey
	 *            JCE ECPrivateKeySpec object
	 * @return A new ECPrivateKey object with the values of the passed
	 *         privateKey
	 * @throws CryptoUtilsException
	 */
	public static ECPrivateKey parse(ECPrivateKeySpec privateKey)
			throws CryptoUtilsException {
		ECPrivateKey privateKeyRes = new ECPrivateKey(
				ECDomainParameters.parse(privateKey.getParams()),
				privateKey.getS());
		return privateKeyRes;
	}

	/**
	 * Parse the calling object to JCE ECPrivateKeySpec type (
	 * {@link java.security.spec.ECPrivateKeySpec})
	 * 
	 * @return A ECPrivateKeySpec with the values of the calling object
	 * @throws CryptoUtilsException
	 */
	public ECPrivateKeySpec parseToECPrivateKeySpec()
			throws CryptoUtilsException {
		ECPrivateKeySpec privateKey = new ECPrivateKeySpec(this.d,
				params.parseToJCEECParameterSpec());
		return privateKey;
	}

	/**
	 * Parse the SpongyCastle ECPrivateKeySpec (
	 * {@link org.spongycastle.jce.spec.ECPrivateKeySpec})
	 * 
	 * @param privateKey
	 *            SpongyCastle ECPrivateKeySpec object
	 * @return A new ECPrivateKey object with the values of the passed
	 *         privateKey
	 * @throws CryptoUtilsException
	 */
	public static ECPrivateKey parse(
			org.spongycastle.jce.spec.ECPrivateKeySpec privateKey)
			throws CryptoUtilsException {
		ECPrivateKey privateKeyRes = new ECPrivateKey(
				ECDomainParameters.parse(privateKey.getParams()),
				privateKey.getD());
		return privateKeyRes;
	}

	/**
	 * Parse the calling object to SpongyCastle ECPrivateKeySpec type (
	 * {@link org.spongycastle.jce.spec.ECPrivateKeySpec})
	 * 
	 * @return A SC ECPrivateKeySpec with the values of the calling object
	 */
	public org.spongycastle.jce.spec.ECPrivateKeySpec parseToSCECPrivateKeySpec() {
		org.spongycastle.jce.spec.ECPrivateKeySpec privateKey = new org.spongycastle.jce.spec.ECPrivateKeySpec(
				this.d, params.parseToECParameterSpec());
		return privateKey;
	}

	/**
	 * Parse the JCE ECPrivateKeySpec (
	 * {@link java.security.spec.ECPrivateKeySpec})
	 * 
	 * @param privateKey
	 *            JCE ECPrivateKeySpec object
	 * @return A new ECPrivateKey object with the values of the passed
	 *         privateKey
	 * @throws CryptoUtilsException
	 */
	public static ECPrivateKey parse(
			java.security.interfaces.ECPrivateKey privateKey)
			throws CryptoUtilsException {
		ECPrivateKey privateKeyRes = new ECPrivateKey(
				ECDomainParameters.parse(privateKey.getParams()),
				privateKey.getS());
		return privateKeyRes;
	}

	/**
	 * Parse the calling object to JCE ECPrivateKey type (
	 * {@link java.security.interfaces.ECPrivateKey})
	 * 
	 * @return A JCE ECPrivateKey with the values of the calling object
	 * @throws CryptoUtilsException
	 */
	public JCEECPrivateKey parseToJCEECPrivateKey() throws CryptoUtilsException {
		JCEECPrivateKey privateKeyAux = new JCEECPrivateKey("EC",
				parseToSCECPrivateKeySpec());

		return privateKeyAux;
	}

	/**
	 * Generic parser
	 * 
	 * @param privateKey
	 *            EC Private key object, supported object types are:
	 *            {@link org.spongycastle.crypto.params.ECPrivateKeyParameter},
	 *            {@link java.security.spec.ECPrivateKeySpec} ,
	 *            {@link java.security.interfaces.ECPrivateKey},
	 *            {@link org.spongycastle.jce.spec.ECPrivateKeySpec}
	 * @throws CryptoUtilsException
	 */
	public static ECPrivateKey parse(Object privateKey)
			throws CryptoUtilsException {
		if (privateKey instanceof ECPrivateKeyParameters) {
			return parse((ECPrivateKeyParameters) privateKey);
		} else if (privateKey instanceof java.security.interfaces.ECPrivateKey) {
			return parse((java.security.interfaces.ECPrivateKey) privateKey);
		} else if (privateKey instanceof org.spongycastle.jce.spec.ECPrivateKeySpec) {
			return parse((org.spongycastle.jce.spec.ECPrivateKeySpec) privateKey);
		} else if (privateKey instanceof ECPrivateKeySpec) {
			return parse((ECPrivateKeySpec) privateKey);
		} else {
			throw new CryptoUtilsException(
					"Parse error: Private key object type not supported");
		}
	}

	/**
	 * Save the EC Private key in Plain PKCS8 format using DER encoding
	 * 
	 * @param privateKeyfullPath
	 *            Full path with file name in which the key will be saved
	 * @throws CryptoUtilsException
	 */
	public void savePKCS8DER(String privateKeyfullPath)
			throws CryptoUtilsException {

		byte[] keyBytes;
		try {

			// PrivateKeyInfo info = new PrivateKeyInfo(new AlgorithmIdentifier(
			// X9ObjectIdentifiers.id_ecPublicKey,
			// params.parseToX9ECParameters()),
			// new org.spongycastle.asn1.sec.ECPrivateKey(this.getD()));
			// info.getEncoded("DER");
			keyBytes = parseToJCEECPrivateKey().getEncoded();

			File file = new File(privateKeyfullPath);
			FileOutputStream fos = new FileOutputStream(file);

			fos.write(keyBytes);
			fos.flush();
			fos.close();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			throw new CryptoUtilsException(
					"Save EC Private Key as Plain PKCS8 DER file error: " + e,
					e);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			throw new CryptoUtilsException(
					"Save EC Private Key as Plain PKCS8 DER file error: " + e,
					e);
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
	public static ECPrivateKey loadPKCS8DER(String privateKeyFullPath)
			throws CryptoUtilsException {
		try {
			File file = new File(privateKeyFullPath);
			if (file.exists()) {
				FileInputStream fis;

				fis = new FileInputStream(file);

				byte[] key = new byte[(int) file.length()];
				fis.read(key);
				fis.close();

				KeyFactory fact = KeyFactory.getInstance("ECDSA",
						CryptoUtils.PROVIDER);

				return ECPrivateKey
						.parse((java.security.interfaces.ECPrivateKey) fact
								.generatePrivate(new PKCS8EncodedKeySpec(key)));

			} else {
				throw new CryptoUtilsException(
						"EC Private Key file not found :" + privateKeyFullPath);
			}
		} catch (FileNotFoundException e) {
			throw new CryptoUtilsException(
					"Load EC Private Key from DER file error: " + e, e);
		} catch (IOException e) {
			throw new CryptoUtilsException(
					"Load EC Private Key from DER file error: " + e, e);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			throw new CryptoUtilsException(
					"Load EC Private Key from DER file error: " + e, e);
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			throw new CryptoUtilsException(
					"Load EC Private Key from DER file error: " + e, e);
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			throw new CryptoUtilsException(
					"Load EC Private Key from DER file error: " + e, e);
		} catch (IllegalArgumentException e) {
			throw new CryptoUtilsException(
					"Load EC Private Key from DER file error: " + e, e);
		}
	}

	/**
	 * Read an Encrypted EC Private Key from the specified file
	 * 
	 * @param filePath
	 *            File that contains the EC Private Key
	 * @param password
	 *            Password of the encrypted file
	 * @throws CryptoUtilsException
	 */
	public static ECPrivateKey loadPKCS8PEM(String filePath, String password)
			throws CryptoUtilsException {

		File file = new File(filePath);
		if (!file.exists()) {
			throw new CryptoUtilsException(
					"Load EC Private Key from PKCS8 PEM file error: File ["
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
			// TODO Auto-generated catch block
			throw new CryptoUtilsException(
					"Load EC Private Key from PKCS8 PEM file error: " + e, e);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			throw new CryptoUtilsException(
					"Load EC Private Key from PKCS8 PEM file error: " + e, e);
		}
	}

	/**
	 * Read an Encrypted EC Private Key from the specified file
	 * 
	 * @param filePath
	 * @throws CryptoUtilsException
	 */
	public static ECPrivateKey loadPKCS8PEM(String filePath)
			throws CryptoUtilsException {
		File file = new File(filePath);
		if (!file.exists()) {
			throw new CryptoUtilsException(
					"Load EC Private Key from PKCS8 PEM file error: File ["
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
			// TODO Auto-generated catch block
			throw new CryptoUtilsException(
					"Load EC Private Key from PKCS8 PEM file error: " + e, e);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			throw new CryptoUtilsException(
					"Load EC Private Key from PKCS8 PEM file error: " + e, e);
		}
	}

	/**
	 * Save this ECPrivateKey to a file using encrypted PKCS8 PEM format
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

			// pkcs8 = new PKCS8Generator(this.parseToJCEECPrivateCrtKey(),
			// selectAlgorithmID(algorithm, "PEM"), //
			// AndroidCryptoUtils.PROVIDER);

			pkcs8 = new PKCS8Generator(this.parseToJCEECPrivateKey(),
					CryptoUtils.selectAlgorithmID(algorithm, "PEM"),
					CryptoUtils.PROVIDER);

			pkcs8.setPassword(password.toCharArray());

			// pWrt.writeObject(parseToJCEECPrivateCrtKey(), algorithm,
			// password.toCharArray(), AndroidCryptoUtils.secureRandom);

			pWrt.writeObject(pkcs8);

			pWrt.close();

		} catch (NoSuchProviderException e) {
			throw new CryptoUtilsException(
					"Save EC Private Key as PKCS8 PEM file error: " + e, e);
		} catch (NoSuchAlgorithmException e) {
			throw new CryptoUtilsException(
					"Save EC Private Key as PKCS8 PEM file error: " + e, e);
		} catch (IOException e) {
			throw new CryptoUtilsException(
					"Save EC Private Key as PKCS8 PEM file error: " + e, e);
		}
	}

	/**
	 * Save this ECPrivateKey to a file using plain PKCS8 PEM format
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

			pkcs8 = new PKCS8Generator(this.parseToJCEECPrivateKey());

			pWrt.writeObject(pkcs8);

			pWrt.close();

		} catch (IOException e) {
			throw new CryptoUtilsException(
					"Save EC Private Key as PKCS8 PEM file error: " + e, e);
		}
	}

	/**
	 * Encodes this ECPrivateKey object as a base64 encoded byte array using PEM
	 * and protected using a password
	 * 
	 * @param password
	 *            Password to protect the key
	 * @throws CryptoUtilsException
	 */
	public byte[] encode(String password) throws CryptoUtilsException {
		try {
			StringWriter wrt = new StringWriter();
			PEMWriter pWrt = new PEMWriter(wrt, CryptoUtils.PROVIDER);

			PKCS8Generator pkcs8;

			pkcs8 = new PKCS8Generator(this.parseToJCEECPrivateKey(),
					CryptoUtils.selectAlgorithmID(CryptoUtils.AES_256_CBC,
							"PEM"), CryptoUtils.PROVIDER);

			pkcs8.setPassword(password.toCharArray());

			// pWrt.writeObject(parseToJCEECPrivateCrtKey(), algorithm,
			// password.toCharArray(), AndroidCryptoUtils.secureRandom);

			pWrt.writeObject(pkcs8);
			pWrt.close();

			return Base64.encode(wrt.toString().getBytes());

		} catch (NoSuchProviderException e) {
			throw new CryptoUtilsException("Encode EC Private Key error: " + e,
					e);
		} catch (NoSuchAlgorithmException e) {
			throw new CryptoUtilsException("Encode EC Private Key error: " + e,
					e);
		} catch (IOException e) {
			throw new CryptoUtilsException("Encode EC Private Key error: " + e,
					e);
		}
	}

	/**
	 * Decodes a byte array encoded using base64 to an ECPrivateKey object
	 * 
	 * @param keyBytes
	 *            Base64 encoded byte array representing the key
	 * @param password
	 *            Password used for encoding the key
	 * @return A new ECPrivateKey that correspond to the encoded bytes
	 * @throws CryptoUtilsException
	 *             if the byte array does not correspond to a Base64
	 *             ECPrivateKey encoded key
	 */
	public static ECPrivateKey decode(byte[] keyBytes, String password)
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
			throw new CryptoUtilsException("Decode EC Private Key error: " + e,
					e);
		}
	}

}