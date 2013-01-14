/**
 *  Created on  : 14/04/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	
 */
package cinvestav.android.pki.cryptography.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException;

import org.spongycastle.jce.provider.BouncyCastleProvider;

import cinvestav.android.pki.cryptography.exception.CryptoUtilsException;

/**
 * @author Ing. Javier Silva Pérez - [javier]
 * 
 */
public class KeyStoreUtil implements IKeyStoreUtils {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	/**
	 * 
	 */
	public KeyStoreUtil() {
		// TODO Auto-generated constructor stub
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.cryptography.android.utils.IKeyStoreUtils#createNewKeyStore ()
	 */
	@Override
	public KeyStore createNewKeyStore() throws CryptoUtilsException {

		KeyStore ks;
		try {
			ks = KeyStore.getInstance("BKS", CryptoUtils.PROVIDER);
			ks.load(null, null);
			return ks;
		} catch (KeyStoreException e) {

			throw new CryptoUtilsException("Error creating the KeyStore: "
					+ e.getMessage(), e);
		} catch (NoSuchProviderException e) {

			throw new CryptoUtilsException("Error creating the KeyStore: "
					+ e.getMessage(), e);
		} catch (NoSuchAlgorithmException e) {

			throw new CryptoUtilsException("Error creating the KeyStore: "
					+ e.getMessage(), e);
		} catch (CertificateException e) {

			throw new CryptoUtilsException("Error creating the KeyStore: "
					+ e.getMessage(), e);
		} catch (IOException e) {

			throw new CryptoUtilsException("Error creating the KeyStore: "
					+ e.getMessage(), e);
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see cinvestav.cryptography.android.utils.IKeyStoreUtils#saveKeyStore
	 * (java.security.KeyStore, java.lang.String, java.lang.String)
	 */
	@Override
	public void saveKeyStore(KeyStore ks, String keyStoreFullPath,
			String password) throws CryptoUtilsException {

		File file = new File(keyStoreFullPath);
		FileOutputStream fos;
		try {
			fos = new FileOutputStream(file);
			ks.store(fos, password.toCharArray());
			fos.flush();
			fos.close();
		} catch (FileNotFoundException e) {

			throw new CryptoUtilsException("Error storing the KeyStore: "
					+ e.getMessage(), e);
		} catch (KeyStoreException e) {

			throw new CryptoUtilsException("Error storing the KeyStore: "
					+ e.getMessage(), e);
		} catch (NoSuchAlgorithmException e) {

			throw new CryptoUtilsException("Error storing the KeyStore: "
					+ e.getMessage(), e);
		} catch (CertificateException e) {
			throw new CryptoUtilsException("Error storing the KeyStore: "
					+ e.getMessage(), e);
		} catch (IOException e) {
			throw new CryptoUtilsException("Error storing the KeyStore: "
					+ e.getMessage(), e);
		}

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see cinvestav.cryptography.android.utils.IKeyStoreUtils#loadKeyStore
	 * (java.lang.String, java.lang.String)
	 */
	@Override
	public KeyStore loadKeyStore(String keyStoreFullPath,
			String keyStorePassword) throws CryptoUtilsException {
		KeyStore ks;
		File keyStoreFile = new File(keyStoreFullPath);
		FileInputStream fis = null;
		try {

			fis = new FileInputStream(keyStoreFile);
		} catch (FileNotFoundException ex) {
			throw new CryptoUtilsException("KeyStoreFile doesn´t exist: "
					+ ex.getMessage(), ex);
		}
		try {
			ks = KeyStore.getInstance("BKS", CryptoUtils.PROVIDER);
			ks.load(fis, keyStorePassword.toCharArray());
			fis.close();
			return ks;
		} catch (KeyStoreException e) {

			throw new CryptoUtilsException("Error loading the KeyStore File: "
					+ e.getMessage(), e);
		} catch (NoSuchProviderException e) {
			throw new CryptoUtilsException("Error loading the KeyStore File: "
					+ e.getMessage(), e);

		} catch (IOException ex) {
			throw new CryptoUtilsException(
					"Error loading the KeyStore File: Wrong file format\n"
							+ ex.getMessage(), ex);
		} catch (NoSuchAlgorithmException ex) {
			throw new CryptoUtilsException(
					"Error loading the KeyStore File: the algorithm used to check the integrity of the keystore cannot be found\n"
							+ ex.getMessage(), ex);
		} catch (CertificateException e) {

			throw new CryptoUtilsException(
					"Error loading the KeyStore File: any of the certificates in the keystore could not be loaded\n"
							+ e.getMessage(), e);
		} finally {
			try {
				fis.close();
			} catch (IOException e) {
				throw new CryptoUtilsException(
						"Error loading the KeyStore File: Wrong file format\n"
								+ e.getMessage(), e);
			}
		}

	}

}
