/**
 *  Created on  : 09/08/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	Interface for Digest functions, contains common functions for create digest
 * using different algorithms
 */
package cinvestav.android.pki.cryptography.utils;

import cinvestav.android.pki.cryptography.exception.CryptoUtilsException;

/**
 * Interface for Digest functions, contains common functions for create digest
 * using different algorithms
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 09/08/2012
 * @version 1.0
 */
public interface IDigestCryptoUtils {

	/**
	 * Get the digest of the input using a desired algorithm,
	 * 
	 * @param input
	 *            Input to the digest function
	 * @param algorithm
	 *            Algorithm that will be used as digest, see available
	 *            algorithms at {@link CryptoUtils} ej.
	 *            CryptoUtils.DIGEST_FUNCTION_SHA_1
	 * @return a byte array representing the digest of the input
	 * @throws CryptoUtilsException
	 *             If the name does not correspond to a supported digest
	 *             algorithm
	 */
	public byte[] getDigest(byte[] input, String algorithm)
			throws CryptoUtilsException;

	/**
	 * Get the digest of the input using SHA-1 as digest algorithm,
	 * 
	 * @param input
	 *            Input to the digest function
	 * @return a byte array representing the digest of the input
	 * @throws CryptoUtilsException
	 *             If the name does not correspond to a supported digest
	 *             algorithm
	 */
	public byte[] getDigest(byte[] input) throws CryptoUtilsException;

	/**
	 * Get the digest of the input string using a desired algorithm
	 * 
	 * @param input
	 *            Input to the digest function
	 * @param algorithm
	 *            Algorithm that will be used as digest, see available
	 *            algorithms at {@link CryptoUtils} ej.
	 *            CryptoUtils.DIGEST_FUNCTION_SHA_1
	 * @param encoder
	 *            Base64 or HEX encoder to be used
	 * @return a string encoded using the selected encoder representing the
	 *         digest of the input
	 * @throws CryptoUtilsException
	 *             If the name does not correspond to a supported digest
	 *             algorithm
	 */
	public String getDigest(String input, String algorithm, String encoder)
			throws CryptoUtilsException;

	/**
	 * Get the digest of the input string using a desired algorithm,
	 * 
	 * @param input
	 *            Input to the digest function
	 * @param algorithm
	 *            Algorithm that will be used as digest, see available
	 *            algorithms at {@link CryptoUtils} ej.
	 *            CryptoUtils.DIGEST_FUNCTION_SHA_1
	 * @return a string encoded using Base64 that represents the digest of the
	 *         input
	 * @throws CryptoUtilsException
	 *             If the name does not correspond to a supported digest
	 *             algorithm
	 */
	public String getDigest(String input, String algorithm)
			throws CryptoUtilsException;

	/**
	 * Get the digest of the input string using SHA-1 algorithm
	 * 
	 * @param input
	 *            Input to the digest function
	 * @return a string encoded using Base64 that represents the digest of the
	 *         input
	 * @throws CryptoUtilsException
	 *             If the name does not correspond to a supported digest
	 *             algorithm
	 */
	public String getDigest(String input) throws CryptoUtilsException;
}
