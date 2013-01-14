/**
 *  Created on  : 07/05/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	RSA Key Pair abstraction, contains both public and private keys
 */
package cinvestav.android.pki.cryptography.key;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.Enumeration;

import org.spongycastle.asn1.x509.SubjectKeyIdentifier;
import org.spongycastle.crypto.AsymmetricCipherKeyPair;
import org.spongycastle.crypto.params.RSAKeyParameters;
import org.spongycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.util.encoders.Base64;
import org.spongycastle.util.encoders.Hex;

import cinvestav.android.pki.cryptography.exception.CryptoUtilsException;
import cinvestav.android.pki.cryptography.utils.CryptoUtils;

/**
 * RSA Key Pair abstraction, contains both public and private keys
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * 
 */
public class RSAKeyPair {

   public void removeYou()
   {
   }

	static {
		Security.addProvider(new BouncyCastleProvider());
	}
	private RSAPrivateKey privateKey;
	private RSAPublicKey publicKey;

	/**
	 * Default constructor
	 * 
	 */
	public RSAKeyPair() {
		super();
		this.privateKey = new RSAPrivateKey();
		this.publicKey = new RSAPublicKey();

	}

	/**
	 * Copy constructor
	 * 
	 * @param rsaKeyPair
	 *            Source key pair
	 */
	public RSAKeyPair(RSAKeyPair rsaKeyPair) {
		this.publicKey = new RSAPublicKey(rsaKeyPair.publicKey);
		this.privateKey = new RSAPrivateKey(rsaKeyPair.privateKey);
	}

	/**
	 * Constructor with parameters, init both public and private key
	 * 
	 * @param privateKey
	 * @param publicKey
	 */
	public RSAKeyPair(RSAPrivateKey privateKey, RSAPublicKey publicKey) {
		super();
		this.privateKey = privateKey;
		this.publicKey = publicKey;
	}

	public RSAPrivateKey getPrivateKey() {
		return privateKey;
	}

	public void setPrivateKey(RSAPrivateKey privateKey) {
		this.privateKey = privateKey;
	}

	public RSAPublicKey getPublicKey() {
		return publicKey;
	}

	public void setPublicKey(RSAPublicKey publicKey) {
		this.publicKey = publicKey;
	}

	@Override
	public String toString() {
		return "RSAKeyPair [privateKey=" + privateKey + ", publicKey="
				+ publicKey + "]";
	}

	/**
	 * ToString method using a specific encoder
	 * 
	 * @param encoder
	 *            see available encoders in
	 *            {@link cinvestav.android.pki.cryptography.utils.CryptoUtils}
	 * @return String Key Pair encoded
	 */
	public String toString(String encoder) {
		return "RSAKeyPair [privateKey=" + privateKey.toString(encoder)
				+ ", publicKey=" + publicKey.toString(encoder) + "]";
	}

	@Override
	public boolean equals(Object obj) {
		if (obj instanceof RSAKeyPair) {
			RSAKeyPair keyPair = (RSAKeyPair) obj;
			boolean res = keyPair.getPrivateKey().equals(this.getPrivateKey())
					&& keyPair.getPublicKey().equals(this.getPublicKey());
			return res;
		} else {
			return false;
		}
	}

	/**
	 * Parse an AsymmetricCipherKeyPair (
	 * {@link org.spongycastle.crypto.AsymmetricCipherKeyPair}) object and
	 * return a new instance of RSAKeyPair
	 * 
	 * @param keyPair
	 *            {@link org.spongycastle.crypto.AsymmetricCipherKeyPair
	 *            AsymmetricCipherKeyPair} object
	 * @throws CryptoUtilsException
	 */
	public static RSAKeyPair parse(AsymmetricCipherKeyPair keyPair)
			throws CryptoUtilsException {
		return new RSAKeyPair(
				RSAPrivateKey.parse((RSAPrivateCrtKeyParameters) keyPair
						.getPrivate()),
				RSAPublicKey.parse((RSAKeyParameters) keyPair.getPublic()));

	}

	/**
	 * Parse java JCE KeyPair ({@link java.security.KeyPair}) to RSA Key Pair
	 * 
	 * @param keyPair
	 * @throws CryptoUtilsException
	 */
	public static RSAKeyPair parse(KeyPair keyPair) throws CryptoUtilsException {
		if (!(keyPair.getPrivate() instanceof RSAPrivateCrtKey)) {
			throw new CryptoUtilsException(
					"Parse error: "
							+ keyPair.getPrivate().getClass().toString()
							+ " not an instance of java.security.interfaces.RSAPrivateCrtKey");
		}

		if (!(keyPair.getPublic() instanceof java.security.interfaces.RSAPublicKey)) {
			throw new CryptoUtilsException(
					"Parse error: "
							+ keyPair.getPublic().getClass().toString()
							+ " not an instance of java.security.interfaces.RSAPublicKey");
		}
		return new RSAKeyPair(RSAPrivateKey.parse((RSAPrivateCrtKey) keyPair
				.getPrivate()),
				RSAPublicKey
						.parse((java.security.interfaces.RSAPublicKey) keyPair
								.getPublic()));

	}

	/**
	 * Parse the current object to Java JCE Key Pair (
	 * {@link java.security.KeyPair})
	 * 
	 * @return JCE Key Pair object
	 * @throws CryptoUtilsException
	 */
	public KeyPair parseToKeyPair() throws CryptoUtilsException {

		return new KeyPair(publicKey.parseToJCERSAPublicKey(),
				privateKey.parseToJCERSAPrivateCrtKey());

	}

	/**
	 * Parse the current object to AsymmetricCipherKeyPair (
	 * {@link org.spongycastle.crypto.AsymmetricCipherKeyPair})
	 * 
	 * @return AsymmetricCipherKeyPair object containing to the current private
	 *         key
	 */
	public AsymmetricCipherKeyPair parseToAsymmetricCipherKeyPair() {
		AsymmetricCipherKeyPair keyPair = new AsymmetricCipherKeyPair(
				this.publicKey.parseToRSAKeyParameters(),
				this.privateKey.parseToRSAPrivateCrtKeyParameters());
		return keyPair;
	}

	/**
	 * Creates a new PKCS12 file, in which is stored the RSA SubjetsPrivate key
	 * protected by PBE and the certificate chain for the corresponding public
	 * key
	 * 
	 * @param fileName
	 *            File name for the pkcs12 file (commonly with extension .p12)
	 * @param keyStorePwd
	 *            Password for the pkcs12 file
	 * @param privKeyPwd
	 *            File for the encrypting the private key
	 * @param chain
	 *            Certificate Chain, must include at least one, containing the
	 *            subject public key
	 * @throws CryptoUtilsException
	 */
	public void savePKCS12(String fileName, String keyStorePwd,
			String privKeyPwd, Certificate[] chain) throws CryptoUtilsException {

		if (chain.length < 1) {
			throw new CryptoUtilsException(
					"Save PKCS12 error: No public certificate related to the privateKey found");
		}
		try {

			SubjectKeyIdentifier keyID = SubjectKeyIdentifier
					.getInstance(CryptoUtils.jcaX509ExtensionUtils
							.createSubjectKeyIdentifier(chain[0].getPublicKey()));
			String keyIDStr = new String(Hex.encode(keyID.getKeyIdentifier()));

			//
			// store the key and the certificate chain
			//
			KeyStore store;
			store = KeyStore.getInstance("PKCS12", CryptoUtils.PROVIDER);
			store.load(null, null);

			//
			// if you haven't set the friendly name and local key id above
			// the name below will be the name of the key
			//
			store.setKeyEntry(keyIDStr, this.getPrivateKey()
					.parseToJCERSAPrivateCrtKey(), privKeyPwd.toCharArray(),
					chain);

			FileOutputStream fOut = new FileOutputStream(fileName);

			store.store(fOut, keyStorePwd.toCharArray());

			fOut.close();
		} catch (KeyStoreException e) {

			throw new CryptoUtilsException("Save PKCS12 error: " + e, e);
		} catch (NoSuchAlgorithmException e) {

			throw new CryptoUtilsException("Save PKCS12 error: " + e, e);
		} catch (CertificateException e) {

			throw new CryptoUtilsException("Save PKCS12 error: " + e, e);
		} catch (IOException e) {

			throw new CryptoUtilsException("Save PKCS12 error: " + e, e);
		} catch (Exception e) {

			e.printStackTrace();
			throw new CryptoUtilsException("Save PKCS12 error: " + e, e);
		}
	}

	/**
	 * Loads the RSA Key Pair stored in a pkcs12
	 * 
	 * @param fileName
	 *            File in which are stored the keys
	 * @param keyStorePwd
	 *            PKCS12 File password
	 * @param privKeyPwd
	 *            PrivateKey Password
	 * @return a object array with 2 positions, in the first one the RSAKeyPair
	 *         stored in the pkcs12 file and in the second one the certificate
	 *         chain stored in the pkcs12 file
	 * @throws CryptoUtilsException
	 */
	public static Object[] loadPKCS12(String fileName, String keyStorePwd,
			String privKeyPwd) throws CryptoUtilsException {

		// KeyStore store;
		RSAPrivateKey privateKey;
		RSAPublicKey publicKey;

		try {
			// Load the key Store
			FileInputStream fin = new FileInputStream(fileName);

			// store = KeyStore.getInstance("PKCS12",
			// AndroidCryptoUtils.PROVIDER);
			KeyStore store;
			store = KeyStore.getInstance("PKCS12", CryptoUtils.PROVIDER);
			store.load(fin, keyStorePwd.toCharArray());
			fin.close();

			Enumeration<String> alias = store.aliases();
			// Iterate the store and gets the first pair of public and private
			// key stored in it
			while (alias.hasMoreElements()) {
				// Get the key alias
				String keyAlias = alias.nextElement();
				if (store.isKeyEntry(keyAlias)) {

					// Load the private key using the key password
					privateKey = RSAPrivateKey.parse(store.getKey(keyAlias,
							privKeyPwd.toCharArray()));

					// Load the certificate chain of the keystore
					Certificate[] chain = store.getCertificateChain(keyAlias);
					// Gets the public key stored in the first certificate
					publicKey = RSAPublicKey.parse(chain[0].getPublicKey());
					Object[] res = new Object[2];
					res[0] = new RSAKeyPair(privateKey, publicKey);
					res[1] = chain;
					return res;
				}
			}

			// If no elements were found in the key store throws and exception
			throw new CryptoUtilsException(
					"Load PKCS12 Certificate chain error: Empty key store");

		} catch (KeyStoreException e) {
			throw new CryptoUtilsException(
					"Load PKCS12 RSAKeyPair error: " + e, e);
		} catch (FileNotFoundException e) {
			throw new CryptoUtilsException(
					"Load PKCS12 RSAKeyPair error: " + e, e);
		} catch (NoSuchAlgorithmException e) {
			throw new CryptoUtilsException(
					"Load PKCS12 RSAKeyPair error: " + e, e);
		} catch (CertificateException e) {
			throw new CryptoUtilsException(
					"Load PKCS12 RSAKeyPair error: " + e, e);
		} catch (IOException e) {
			throw new CryptoUtilsException(
					"Load PKCS12 RSAKeyPair error: " + e, e);
		} catch (UnrecoverableKeyException e) {
			throw new CryptoUtilsException(
					"Load PKCS12 RSAKeyPair error: " + e, e);
		} catch (NoSuchProviderException e) {
			throw new CryptoUtilsException(
					"Load PKCS12 RSAKeyPair error: " + e, e);
		}
	}

	/**
	 * Encode the RSAKeyPair as a PKCS12 byte array using base64, in which is
	 * stored the RSA SubjetsPrivate key protected by PBE and the certificate
	 * chain for the corresponding public key
	 * 
	 * @param keyStorePwd
	 *            Password for the pkcs12 file
	 * @param privKeyPwd
	 *            File for the encrypting the private key
	 * @param chain
	 *            Certificate Chain, must include at least one, containing the
	 *            subject public key
	 * @throws CryptoUtilsException
	 */
	public byte[] encodePKCS12(String keyStorePwd, String privKeyPwd,
			Certificate[] chain) throws CryptoUtilsException {

		if (chain.length < 1) {
			throw new CryptoUtilsException(
					"Save PKCS12 error: No public certificate related to the privateKey found");
		}
		try {

			SubjectKeyIdentifier keyID = SubjectKeyIdentifier
					.getInstance(CryptoUtils.jcaX509ExtensionUtils
							.createSubjectKeyIdentifier(chain[0].getPublicKey()));
			String keyIDStr = new String(Hex.encode(keyID.getKeyIdentifier()));

			//
			// store the key and the certificate chain
			//
			KeyStore store;
			store = KeyStore.getInstance("PKCS12", CryptoUtils.PROVIDER);
			store.load(null, null);

			//
			// if you haven't set the friendly name and local key id above
			// the name below will be the name of the key
			//
			store.setKeyEntry(keyIDStr, this.getPrivateKey()
					.parseToJCERSAPrivateCrtKey(), privKeyPwd.toCharArray(),
					chain);

			ByteArrayOutputStream fOut = new ByteArrayOutputStream();

			store.store(fOut, keyStorePwd.toCharArray());

			fOut.close();

			return Base64.encode(fOut.toByteArray());
		} catch (KeyStoreException e) {

			throw new CryptoUtilsException("Save PKCS12 error: " + e, e);
		} catch (NoSuchAlgorithmException e) {

			throw new CryptoUtilsException("Save PKCS12 error: " + e, e);
		} catch (CertificateException e) {

			throw new CryptoUtilsException("Save PKCS12 error: " + e, e);
		} catch (IOException e) {

			throw new CryptoUtilsException("Save PKCS12 error: " + e, e);
		} catch (Exception e) {

			e.printStackTrace();
			throw new CryptoUtilsException("Save PKCS12 error: " + e, e);
		}
	}

	/**
	 * Decodes a PKCS12 byte array encoded using base64 to an RSAKeyPair object
	 * 
	 * @param pairBytes
	 *            byte array encoded using base64 which represents the
	 *            RSAKeyPair
	 * @param keyStorePwd
	 *            PKCS12 File password
	 * @param privKeyPwd
	 *            PrivateKey Password
	 * @return a object array with 2 positions, in the first one the RSAKeyPair
	 *         stored in the pkcs12 file and in the second one the certificate
	 *         chain stored in the pkcs12 file
	 * @throws CryptoUtilsException
	 */
	public static Object[] decodePKCS12(byte[] pairBytes, String keyStorePwd,
			String privKeyPwd) throws CryptoUtilsException {

		// KeyStore store;
		RSAPrivateKey privateKey;
		RSAPublicKey publicKey;

		try {
			InputStream input = new ByteArrayInputStream(
					Base64.decode(pairBytes));

			KeyStore store;
			store = KeyStore.getInstance("PKCS12", CryptoUtils.PROVIDER);
			store.load(input, keyStorePwd.toCharArray());
			input.close();

			Enumeration<String> alias = store.aliases();
			// Iterate the store and gets the first pair of public and private
			// key stored in it
			while (alias.hasMoreElements()) {
				// Get the key alias
				String keyAlias = alias.nextElement();
				if (store.isKeyEntry(keyAlias)) {

					// Load the private key using the key password
					privateKey = RSAPrivateKey.parse(store.getKey(keyAlias,
							privKeyPwd.toCharArray()));

					// Load the certificate chain of the keystore
					Certificate[] chain = store.getCertificateChain(keyAlias);
					// Gets the public key stored in the first certificate
					publicKey = RSAPublicKey.parse(chain[0].getPublicKey());
					Object[] res = new Object[2];
					res[0] = new RSAKeyPair(privateKey, publicKey);
					res[1] = chain;
					return res;
				}
			}

			// If no elements were found in the key store throws and exception
			throw new CryptoUtilsException(
					"Load PKCS12 Certificate chain error: Empty key store");

		} catch (KeyStoreException e) {
			throw new CryptoUtilsException(
					"Load PKCS12 RSAKeyPair error: " + e, e);
		} catch (FileNotFoundException e) {
			throw new CryptoUtilsException(
					"Load PKCS12 RSAKeyPair error: " + e, e);
		} catch (NoSuchAlgorithmException e) {
			throw new CryptoUtilsException(
					"Load PKCS12 RSAKeyPair error: " + e, e);
		} catch (CertificateException e) {
			throw new CryptoUtilsException(
					"Load PKCS12 RSAKeyPair error: " + e, e);
		} catch (IOException e) {
			throw new CryptoUtilsException(
					"Load PKCS12 RSAKeyPair error: " + e, e);
		} catch (UnrecoverableKeyException e) {
			throw new CryptoUtilsException(
					"Load PKCS12 RSAKeyPair error: " + e, e);
		} catch (NoSuchProviderException e) {
			throw new CryptoUtilsException(
					"Load PKCS12 RSAKeyPair error: " + e, e);
		}
	}
}
