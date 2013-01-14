/**
 *  Created on  : 08/06/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	
 */
package cinvestav.android.pki.cryptography.key;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Enumeration;

import org.spongycastle.asn1.x509.SubjectKeyIdentifier;
import org.spongycastle.crypto.AsymmetricCipherKeyPair;
import org.spongycastle.crypto.params.ECPrivateKeyParameters;
import org.spongycastle.crypto.params.ECPublicKeyParameters;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.util.encoders.Base64;
import org.spongycastle.util.encoders.Hex;

import cinvestav.android.pki.cryptography.ec.ECDomainParameters;
import cinvestav.android.pki.cryptography.ec.ECPointF2m;
import cinvestav.android.pki.cryptography.ec.ECPointFp;
import cinvestav.android.pki.cryptography.exception.CryptoUtilsException;
import cinvestav.android.pki.cryptography.utils.CryptoUtils;

/**
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 08/06/2012
 * @version 1.0
 */
public class ECKeyPair {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	private ECPrivateKey privateKey;
	private ECPublicKey publicKey;

	public ECKeyPair(ECKeyPair keyPair) throws CryptoUtilsException {
		this.privateKey = keyPair.getPrivateKey();
		this.publicKey = keyPair.getPublicKey();
	}

	/**
	 * @return the privateKey
	 */
	public ECPrivateKey getPrivateKey() {
		return privateKey;
	}

	/**
	 * @param privateKey
	 *            the privateKey to set
	 */
	public void setPrivateKey(ECPrivateKey privateKey) {
		this.privateKey = privateKey;
	}

	/**
	 * @return the publicKey
	 */
	public ECPublicKey getPublicKey() {
		return publicKey;
	}

	/**
	 * @param publicKey
	 *            the publicKey to set
	 */
	public void setPublicKey(ECPublicKey publicKey) {
		this.publicKey = publicKey;
	}

	/**
	 * ECKeyPair constructor, which receives both public and privateKeys
	 * 
	 * @param privateKey
	 *            Private part of the key
	 * @param publicKey
	 *            Public part of the key
	 * @throws CryptoUtilsException
	 *             If the fields of the keys and points are not the same
	 */
	public ECKeyPair(ECPrivateKey privateKey, ECPublicKey publicKey)
			throws CryptoUtilsException {
		this.privateKey = new ECPrivateKey(privateKey);

		Object publicPoint = publicKey.getQ();
		if (publicPoint instanceof ECPointFp) {
			this.publicKey = new ECPublicKey(publicKey.getParams(),
					publicKey.getQFp());
		} else if (publicPoint instanceof ECPointF2m) {
			this.publicKey = new ECPublicKey(publicKey.getParams(),
					publicKey.getQF2m());
		}
	}

	/**
	 * Constructor that receives each parameter for construct the key over Fp
	 * 
	 * @param parameters
	 *            Curve parameters
	 * @param privateKeyPart
	 *            Private part of the key (BigInter)
	 * @param publicKeyPoint
	 *            Point that represents the public part of the key
	 * @throws CryptoUtilsException
	 *             If the point and the parameters does not correspond to the
	 *             same field
	 */
	public ECKeyPair(ECDomainParameters parameters, BigInteger privateKeyPart,
			ECPointFp publicKeyPoint) throws CryptoUtilsException {
		this.privateKey = new ECPrivateKey(parameters, privateKeyPart);
		this.publicKey = new ECPublicKey(parameters, publicKeyPoint);
	}

	/**
	 * Constructor that receives each parameter for construct the key over Fp
	 * 
	 * @param parameters
	 *            Curve parameters
	 * @param privateKeyPart
	 *            Private part of the key (BigInter)
	 * @param publicKeyPoint
	 *            Point that represents the public part of the key
	 * @throws CryptoUtilsException
	 *             If the point and the parameters does not correspont to the
	 *             same field
	 */
	public ECKeyPair(ECDomainParameters parameters, BigInteger privateKeyPart,
			ECPointF2m publicKeyPoint) throws CryptoUtilsException {
		this.privateKey = new ECPrivateKey(parameters, privateKeyPart);
		this.publicKey = new ECPublicKey(parameters, publicKeyPoint);
	}

	/**
	 * Parse SpongyCastle AsymmetricCipherKeyPair to EC Key Pair, the result of
	 * the parse will returned
	 * 
	 * @param keyPair
	 *            EC Key Pair to be parsed
	 * @return The new ECKeyPair resulting of the parse
	 * @throws CryptoUtilsException
	 *             if the key pair does not correspond to valid EC Keys
	 *             parameters
	 */
	public static ECKeyPair parse(AsymmetricCipherKeyPair keyPair)
			throws CryptoUtilsException {
		if (keyPair.getPrivate() instanceof ECPrivateKeyParameters
				&& keyPair.getPublic() instanceof ECPublicKeyParameters) {
			ECKeyPair res = new ECKeyPair(
					ECPrivateKey.parse((ECPrivateKeyParameters) keyPair
							.getPrivate()),
					ECPublicKey.parse((ECPublicKeyParameters) keyPair
							.getPublic()));
			return res;
		}
		throw new CryptoUtilsException(
				"ECKeyPair parse error: KeyPair parameter does not correspont to valid EC Keys values");
	}

	/**
	 * Parse the calling object to SpongyCastle AsymmetricCipherKeyPair
	 * representation
	 * 
	 * @return New AsymmetricCipherKeyPair object with the key values of the
	 *         current object
	 */
	public AsymmetricCipherKeyPair parseTo() {
		AsymmetricCipherKeyPair tempPair = new AsymmetricCipherKeyPair(
				this.publicKey.parseToECPublicKeyParameters(),
				this.privateKey.parseToECPrivateKeyParameters());
		return tempPair;

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return "ECKeyPair [privateKey=" + privateKey + ", publicKey="
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
		return "ECKeyPair [privateKey=" + privateKey.toString(encoder)
				+ ", publicKey=" + publicKey.toString(encoder) + "]";
	}

	@Override
	public boolean equals(Object obj) {
		if (obj instanceof ECKeyPair) {
			ECKeyPair keyPair = (ECKeyPair) obj;
			boolean res = keyPair.getPrivateKey().equals(this.getPrivateKey())
					&& keyPair.getPublicKey().equals(this.getPublicKey());
			return res;
		} else {
			return false;
		}
	}

	/**
	 * Creates a new PKCS12 file, in which is stored the EC Private key
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
					.parseToJCEECPrivateKey(), privKeyPwd.toCharArray(), chain);

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
	 * Loads the EC Key Pair stored in a pkcs12
	 * 
	 * @param fileName
	 *            File in which are stored the keys
	 * @param keyStorePwd
	 *            PKCS12 File password
	 * @param privKeyPwd
	 *            PrivateKey Password
	 * @return An object array with 2 positions, in the first one the {@link ECKeyPair}
	 *         stored in the pkcs12 file and in the second one the certificate
	 *         chain stored in the pkcs12 file
	 * @throws CryptoUtilsException
	 */
	public static Object[] loadPKCS12(String fileName, String keyStorePwd,
			String privKeyPwd) throws CryptoUtilsException {
		// KeyStore store;
		ECPrivateKey privateKey;
		ECPublicKey publicKey;

		try {
			// Load the key Store
			FileInputStream fin = new FileInputStream(fileName);

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
					privateKey = ECPrivateKey.parse(store.getKey(keyAlias,
							privKeyPwd.toCharArray()));

					// Load the certificate chain of the keystore
					Certificate[] chain = store.getCertificateChain(keyAlias);
					// Gets the public key stored in the first certificate
					publicKey = ECPublicKey.parse(chain[0].getPublicKey());
					Object[] res = new Object[2];
					res[0] = new ECKeyPair(privateKey, publicKey);
					res[1] = chain;
					return res;
				}
			}

			// If no elements were found in the key store throws and exception
			throw new CryptoUtilsException(
					"Load PKCS12 Certificate chain error: Empty key store");

		} catch (KeyStoreException e) {
			throw new CryptoUtilsException("Load PKCS12 ECKeyPair error: " + e,
					e);
		} catch (FileNotFoundException e) {
			throw new CryptoUtilsException("Load PKCS12 ECKeyPair error: " + e,
					e);
		} catch (NoSuchAlgorithmException e) {
			throw new CryptoUtilsException("Load PKCS12 ECKeyPair error: " + e,
					e);
		} catch (CertificateException e) {
			throw new CryptoUtilsException("Load PKCS12 ECKeyPair error: " + e,
					e);
		} catch (IOException e) {
			throw new CryptoUtilsException("Load PKCS12 ECKeyPair error: " + e,
					e);
		} catch (UnrecoverableKeyException e) {
			throw new CryptoUtilsException("Load PKCS12 ECKeyPair error: " + e,
					e);
		} catch (NoSuchProviderException e) {
			throw new CryptoUtilsException("Load PKCS12 ECKeyPair error: " + e,
					e);
		}
	}

	/**
	 * Encode the ECKeyPair as a PKCS12 byte array using base64, in which is
	 * stored the EC Private key protected by PBE and the certificate chain for
	 * the corresponding public key
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
					.parseToJCEECPrivateKey(), privKeyPwd.toCharArray(), chain);

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
	 * Decodes a PKCS12 byte array encoded using base64 to an ECKeyPair object
	 * 
	 * @param pairBytes
	 *            byte array encoded using base64 which represents the
	 *            RSAKeyPair
	 * @param keyStorePwd
	 *            PKCS12 File password
	 * @param privKeyPwd
	 *            PrivateKey Password
	 * @return An object array with 2 positions, in the first one the {@link ECKeyPair}
	 *         stored in the pkcs12 file and in the second one the certificate
	 *         chain stored in the pkcs12 file
	 * @throws CryptoUtilsException
	 */
	public static Object[] decodePKCS12(byte[] pairBytes, String keyStorePwd,
			String privKeyPwd) throws CryptoUtilsException {
		// KeyStore store;
		ECPrivateKey privateKey;
		ECPublicKey publicKey;

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
					privateKey = ECPrivateKey.parse(store.getKey(keyAlias,
							privKeyPwd.toCharArray()));

					// Load the certificate chain of the keystore
					Certificate[] chain = store.getCertificateChain(keyAlias);
					// Gets the public key stored in the first certificate
					publicKey = ECPublicKey.parse(chain[0].getPublicKey());
					Object[] res = new Object[2];
					res[0] = new ECKeyPair(privateKey, publicKey);
					res[1] = chain;
					return res;
				}
			}

			// If no elements were found in the key store throws and exception
			throw new CryptoUtilsException(
					"Load PKCS12 Certificate chain error: Empty key store");

		} catch (KeyStoreException e) {
			throw new CryptoUtilsException("Decode PKCS12 ECKeyPair error: " + e,
					e);
		} catch (FileNotFoundException e) {
			throw new CryptoUtilsException("Decode PKCS12 ECKeyPair error: " + e,
					e);
		} catch (NoSuchAlgorithmException e) {
			throw new CryptoUtilsException("Decode PKCS12 ECKeyPair error: " + e,
					e);
		} catch (CertificateException e) {
			throw new CryptoUtilsException("Decode PKCS12 ECKeyPair error: " + e,
					e);
		} catch (IOException e) {
			throw new CryptoUtilsException("Decode PKCS12 ECKeyPair error: " + e,
					e);
		} catch (UnrecoverableKeyException e) {
			throw new CryptoUtilsException("Decode PKCS12 ECKeyPair error: " + e,
					e);
		} catch (NoSuchProviderException e) {
			throw new CryptoUtilsException("Decode PKCS12 ECKeyPair error: " + e,
					e);
		} catch (Exception e) {
			throw new CryptoUtilsException("Decode PKCS12 ECKeyPair error: " + e,
					e);
		}
	}

}
