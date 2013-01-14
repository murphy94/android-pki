/**
 *  Created on  : 29/05/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	Interface for PGP Utils, contains common functions for PGP compatibility
 */
package cinvestav.android.pki.cryptography.utils;

import java.util.HashMap;

import cinvestav.android.pki.cryptography.exception.CryptoUtilsException;
import cinvestav.android.pki.cryptography.key.RSAKeyPair;
import cinvestav.android.pki.cryptography.key.RSAPrivateKey;
import cinvestav.android.pki.cryptography.key.RSAPublicKey;

/**
 * Interface for PGP Utils, contains common functions for PGP compatibility
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 29/05/2012
 * @version 1.0
 */
public interface IPGPUtils {

	/**
	 * Saves a RSA Public Key un PGP Public Key Format
	 * 
	 * @param fullFileName
	 *            File in which the key will be saved
	 * @param publicKey
	 *            RSA Public Key to save
	 * @param publicKeyInformationMap
	 *            Map filled out with the publicKey owner information to be
	 *            certify using the Field key (
	 *            {@link cinvestav.android.pki.cryptography.cert.CertificateInformationKeys}
	 *            Supported Keys) and the field value
	 * @param issuerKeyPair
	 *            issuerKeyPair used for certify the publicKey information
	 *            (Issuer KeyPair)
	 * @param ascArmor
	 *            If the output file will be saved using ASCII Armor
	 * @throws CryptoUtilsException
	 */
	public void saveRSAPublicKey(String fullFileName, RSAPublicKey publicKey,
			HashMap<String, String> publicKeyInformationMap,
			RSAKeyPair issuerKeyPair, Boolean ascArmor)
			throws CryptoUtilsException;

	/**
	 * Load a RSAPublicKey from a file containing a PGPPublicKey
	 * 
	 * @param fullFileName
	 *            File including its full path, in which the PGPPublicKey is
	 *            located
	 * @return A valid RSAPublicKey
	 * @throws CryptoUtilsException
	 *             if the file does not contain a valid PGPPublicKey
	 */
	public RSAPublicKey loadRSAPublicKey(String fullFileName)
			throws CryptoUtilsException;

	/**
	 * Load the public Key information from a PGPPublicKey file
	 * 
	 * @param fullFileName
	 *            File including its full path, in which the information is
	 *            located in format of a PGPPublicKey
	 * @return A map containing the publicKey owner information, using the Field
	 *         key (
	 *         {@link cinvestav.android.pki.cryptography.cert.CertificateInformationKeys}
	 *         Supported Keys) and the field value
	 * @throws CryptoUtilsException
	 *             if the file does not contain a valid PGPPublicKey
	 */
	public HashMap<String, String> loadPublicKeyInformationMap(
			String fullFileName) throws CryptoUtilsException;

	/**
	 * Saves a RSAPrivateKey in PGP Format
	 * 
	 * @param fullFileName
	 *            File name (full path)
	 * @param privateKey
	 *            RSAPrivateKey to be saved
	 * @param password
	 *            Password for the file
	 * @param ascArmor
	 *            If ASCII Armor should be used to encode the file
	 * @throws CryptoUtilsException
	 */
	public void saveRSAPrivateKey(String fullFileName,
			RSAPrivateKey privateKey, String password, Boolean ascArmor)
			throws CryptoUtilsException;

	/**
	 * Load a RSAPrivateKey from a file in PGPSecretKey format
	 * 
	 * @param fullFileName
	 *            Full path and name of the file containing the PGPSecretKey
	 * @param password
	 *            Password used for open the file
	 * @return a Valid RSAPrivateKey
	 * @throws CryptoUtilsException
	 *             if the file does not contain a valid PGPSecretKey
	 */
	public RSAPrivateKey loadRSAPrivateKey(String fullFileName, String password)
			throws CryptoUtilsException;

	/**
	 * Save a RSAKeyPair in two separate files, in PGP format
	 * 
	 * @param fullRSAPublicKeyFileName
	 *            File in which will be saved the RSAPublicKey
	 * @param fullRSAPrivateKeyFileName
	 *            File in which will be saved the RSAPrivateKey
	 * @param keyPair
	 *            KeyPair to be saved
	 * @param publicKeyInformationMap
	 *            Map filled out with the publicKey owner information to be
	 *            certify using the Field key (
	 *            {@link cinvestav.android.pki.cryptography.cert.CertificateInformationKeys}
	 *            Supported Keys) and the field value
	 * @param issuerKeyPair
	 *            issuerKeyPair used for certify the publicKey information
	 *            (Issuer KeyPair)
	 * @param password
	 *            Password used for the PGPSecretKey
	 * @param ascArmor
	 *            If ASCII Armor should be used or not
	 * @throws CryptoUtilsException
	 */
	public void saveRSAKeyPair(String fullRSAPublicKeyFileName,
			String fullRSAPrivateKeyFileName, RSAKeyPair keyPair,
			HashMap<String, String> publicKeyInformationMap,
			RSAKeyPair issuerKeyPair, String password, Boolean ascArmor)
			throws CryptoUtilsException;

}
