/**
 *  Created on  : 15/03/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	Public interface for Android KeyStore Utils Class, will contain basic keyStore functions
 */
package cinvestav.android.pki.cryptography.utils;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchProviderException;

import cinvestav.android.pki.cryptography.exception.CryptoUtilsException;

/**
 * @author Ing. Javier Silva Pérez - [javier]
 * 
 */
public interface IKeyStoreUtils {

	/**
	 * Creates an empty keystore
	 * @param keyStoreFullPath
	 * @return An empty KeyStore
	 */
	KeyStore createNewKeyStore() throws CryptoUtilsException ;
	
	/**
	 * Stores the keystore into a file
	 * @param ks	KeyStore to save
	 * @param keyStoreFullPath	Full path in which the file will be stored
	 * @param password Password to be used to protect the keystore
	 */
	void saveKeyStore(KeyStore ks, String keyStoreFullPath, String password) throws CryptoUtilsException;

	/**
	 * Load the KeyStore from file
	 * 
	 * @param keyStoreFile
	 *            File containing the keystore of type BKS
	 * @param keyStorePassword
	 *            Password for the keyStore
	 * @return An instance of KeyStore
	 * @throws CryptoUtilsException
	 * @throws KeyStoreException
	 * @throws NoSuchProviderException
	 */
	KeyStore loadKeyStore(String keyStoreFullPath, String keyStorePassword)
			throws CryptoUtilsException;
	
	
	
}
