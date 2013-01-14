/**
 *  Created on  : 14/04/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	
 */
package cinvestav.android.pki.cryptography.utils;

import java.math.BigInteger;
import java.util.List;

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
 * 
 */
public interface IAsymmetricCryptoUtils {

	/**
	 * Sign the hash of the message using RSA
	 * 
	 * @param message
	 *            Original Message to be signed
	 * @param privateKey
	 *            Private Key to be used for sign the message
	 * @param digestName
	 *            Digest Function Name that will be used for hash the message
	 *            and sign the resulting hash
	 * @return Byte array that contains the sign for the message
	 * @throws CryptoUtilsException
	 *             if the digestFunction is not supported, or an error exist
	 *             while signing the message
	 */
	byte[] sign(byte[] message, RSAPrivateKey privateKey, String digestName)
			throws CryptoUtilsException;

	/**
	 * Sign the hash of the message using RSA and SHA-1 as digest function
	 * 
	 * @param message
	 *            Original Message to be signed
	 * @param privateKey
	 *            Private Key to be used for sign the message
	 * @return Byte array that contains the sign for the message
	 * @throws CryptoUtilsException
	 *             if the digestFunction is not supported, or an error exist
	 *             while signing the message
	 */
	byte[] sign(byte[] message, RSAPrivateKey privateKey)
			throws CryptoUtilsException;

	/**
	 * Sign the hash of the message using RSA
	 * 
	 * @param message
	 *            Original Message to be signed
	 * @param privateKey
	 *            Private Key to be used for sign the message
	 * @param digestName
	 *            Digest Function Name that will be used for hash the message
	 *            and sign the resulting hash
	 * @param encoder
	 *            Encode format for the output sign
	 * @return A String that represents the sign encoded with an specific format
	 * @throws CryptoUtilsException
	 *             if the digestFunction or encoder is not supported, or an
	 *             error exist while signing the message
	 */
	String sign(String message, RSAPrivateKey privateKey,
			String digestName, String encoder) throws CryptoUtilsException;

	/**
	 * Sign the hash of the message using RSA using Base64 as default encoder
	 * 
	 * @param message
	 *            Original Message to be signed
	 * @param privateKey
	 *            Private Key to be used for sign the message
	 * @param digestName
	 *            Digest Function Name that will be used for hash the message
	 *            and sign the resulting hash
	 * @return A String that represents the sign encoded with an specific format
	 * @throws CryptoUtilsException
	 *             if the digestFunction or encoder is not supported, or an
	 *             error exist while signing the message
	 */
	String sign(String message, RSAPrivateKey privateKey, String digestName)
			throws CryptoUtilsException;

	/**
	 * Sign the hash of the message using RSA using Base64 as default encoder
	 * and SHA-1 as default digest function
	 * 
	 * @param message
	 *            Original Message to be signed
	 * @param privateKey
	 *            Private Key to be used for sign the message
	 * @return A String that represents the sign encoded with an specific format
	 * @throws CryptoUtilsException
	 *             if the digestFunction or encoder is not supported, or an
	 *             error exist while signing the message
	 */
	String sign(String message, RSAPrivateKey privateKey)
			throws CryptoUtilsException;

	/**
	 * Verify the sign of a message using RSA
	 * 
	 * @param message
	 *            Original message
	 * @param sign
	 *            Sign of the original message
	 * @param publicKey
	 *            Public Key to be used for verify the sign of the message
	 * @param digestName
	 *            Digest function name that will be used for hash the message
	 *            and verify the sign with resulting hash
	 * @return TRUE if the sign is correct, FALSE otherwise
	 * @throws CryptoUtilsException
	 *             if the digestFunction is not supported, or an error exist
	 *             while verifying the signature
	 */
	Boolean verify(byte[] message, byte[] sign, RSAPublicKey publicKey,
			String digestName) throws CryptoUtilsException;

	/**
	 * Verify the sign of a message using RSA and SHA-1 as digest function
	 * 
	 * @param message
	 *            Original message
	 * @param sign
	 *            Sign of the original message
	 * @param publicKey
	 *            Public Key to be used for verify the sign of the message
	 * @return TRUE if the sign is correct, FALSE otherwise
	 * @throws CryptoUtilsException
	 *             if the digestFunction is not supported, or an error exist
	 *             while verifying the signature
	 */
	Boolean verify(byte[] message, byte[] sign, RSAPublicKey publicKey)
			throws CryptoUtilsException;

	/**
	 * Verify the sign of a message using RSA
	 * 
	 * @param message
	 *            Original message
	 * @param sign
	 *            Sign of the original message encoded using the selected encode
	 *            format
	 * @param publicKey
	 *            Public Key to be used for verify the sign of the message
	 * @param digestName
	 *            Digest function name that will be used for hash the message
	 *            and verify the sign with resulting hash
	 * @param encoder
	 *            Encode format of the message and the sign
	 * @return TRUE if the sign is correct, FALSE otherwise
	 * @throws CryptoUtilsException
	 *             if the digestFunction is not supported, or an error exist
	 *             while verifying the signature
	 */
	Boolean verify(String message, String sign, RSAPublicKey publicKey,
			String digestName, String encoder) throws CryptoUtilsException;

	/**
	 * Verify the sign of a message using RSA, using Base64 as default encoder
	 * 
	 * @param message
	 *            Original message
	 * @param sign
	 *            Sign of the original message encoded Base64
	 * @param publicKey
	 *            Public Key to be used for verify the sign of the message
	 * @param digestName
	 *            Digest function name that will be used for hash the message
	 *            and verify the sign with resulting hash
	 * @return TRUE if the sign is correct, FALSE otherwise
	 * @throws CryptoUtilsException
	 *             if the digestFunction is not supported, or an error exist
	 *             while verifying the signature
	 */
	Boolean verify(String message, String sign, RSAPublicKey publicKey,
			String digestName) throws CryptoUtilsException;

	/**
	 * Verify the sign of a message using RSA, using Base64 as default encoder
	 * and SHA-1 as default digest function
	 * 
	 * @param message
	 *            Original message encoded using the selected encode format
	 * @param sign
	 *            Sign of the original message encoded using the selected encode
	 *            format
	 * @param publicKey
	 *            Public Key to be used for verify the sign of the message
	 * @return TRUE if the sign is correct, FALSE otherwise
	 * @throws CryptoUtilsException
	 *             if the digestFunction is not supported, or an error exist
	 *             while verifying the signature
	 */
	Boolean verify(String message, String sign, RSAPublicKey publicKey)
			throws CryptoUtilsException;

	/**
	 * Encrypts byte arrays using the specified key with RSA
	 * 
	 * To encrypt the message, first a random session key is generated and used
	 * for encrypt the input message with a symmetric algorithm (AES-CBC),
	 * finally this key is encrypted with RSA so this function return two
	 * things, the encrypted input message and the encrypted session key
	 * 
	 * @param plainText
	 *            byte array to be encrypted
	 * @param publicKey
	 *            Key to be used in the encryption process
	 * @param operationMode
	 *            Custom Operation mode (check out supported operationModes)
	 * @return A List with 2 elements, first byte array representing the
	 *         encrypted message and secondly the encrypted session key, this
	 *         key was used for encrypt the input message with a symmetric
	 *         algorithm
	 * @throws CryptoUtilsException
	 *             If something goes wrong
	 */
	List<byte[]> encrypt(byte[] plainText, RSAPublicKey publicKey,
			String operationMode) throws CryptoUtilsException;

	/**
	 * Encrypts byte arrays using the specified key with RSA using PKCS1 as
	 * default operation mode
	 * 
	 * To encrypt the message, first a random session key is generated and used
	 * for encrypt the input message with a symmetric algorithm (AES-CBC),
	 * finally this key is encrypted with RSA so this function return two
	 * things, the encrypted input message and the encrypted session key
	 * 
	 * @param plainText
	 *            byte array to be encrypted
	 * @param publicKey
	 *            Key to be used in the encryption process
	 * @return A List with 2 elements, first byte array representing the
	 *         encrypted message and secondly the encrypted session key, this
	 *         key was used for encrypt the input message with a symmetric
	 *         algorithm
	 * @throws CryptoUtilsException
	 *             If something goes wrong
	 */
	List<byte[]> encrypt(byte[] plainText, RSAPublicKey publicKey)
			throws CryptoUtilsException;

	/**
	 * Encrypts encoded text using the specified key with RSA default settings:
	 * none
	 * 
	 * To encrypt the message, first a random session key is generated and used
	 * for encrypt the input message with a symmetric algorithm (AES-CBC),
	 * finally this key is encrypted with RSA so this function return two
	 * things, the encrypted input message and the encrypted session key
	 * 
	 * @param plainText
	 *            Text to be encrypted, must be encoded using the specified
	 *            coder
	 * @param publicKey
	 *            Key to be used in the encryption process
	 * @param encoder
	 *            input Text encode format
	 * @param operationMode
	 *            Custom Operation mode (check out supported operationModes)
	 * @return A List with 2 strings, the first string represents the encrypted
	 *         message and secondly the encrypted session key, this key was used
	 *         for encrypt the input message with a symmetric algorithm
	 * @throws CryptoUtilsException
	 *             If something goes wrong
	 */
	List<String> encrypt(String plainText, RSAPublicKey publicKey,
			String encoder, String operationMode) throws CryptoUtilsException;

	/**
	 * Encrypts encoded text using the specified key with RSA default settings:
	 * PKCS1 operation mode
	 * 
	 * To encrypt the message, first a random session key is generated and used
	 * for encrypt the input message with a symmetric algorithm (AES-CBC),
	 * finally this key is encrypted with RSA so this function return two
	 * things, the encrypted input message and the encrypted session key
	 * 
	 * @param plainText
	 *            Text to be encrypted, must be encoded using the specified
	 *            coder
	 * @param publicKey
	 *            Key to be used in the encryption process
	 * @param encoder
	 *            input Text encode format
	 * @return A List with 2 strings, the first string represents the encrypted
	 *         message and secondly the encrypted session key, this key was used
	 *         for encrypt the input message with a symmetric algorithm
	 * @throws CryptoUtilsException
	 *             If something goes wrong
	 */
	List<String> encrypt(String plainText, RSAPublicKey publicKey,
			String encoder) throws CryptoUtilsException;

	/**
	 * Encrypts encoded text using the specified key with RSA default settings:
	 * PKCS1 operation mode, Base64 encoder
	 * 
	 * To encrypt the message, first a random session key is generated and used
	 * for encrypt the input message with a symmetric algorithm (AES-CBC),
	 * finally this key is encrypted with RSA so this function return two
	 * things, the encrypted input message and the encrypted session key
	 * 
	 * @param plainText
	 *            Text to be encrypted, must be encoded using the specified
	 *            coder
	 * @param publicKey
	 *            Key to be used in the encryption process
	 * @return A List with 2 strings, the first string represents the encrypted
	 *         message and secondly the encrypted session key, this key was used
	 *         for encrypt the input message with a symmetric algorithm
	 * @throws CryptoUtilsException
	 *             If something goes wrong
	 */
	List<String> encrypt(String plainText, RSAPublicKey publicKey)
			throws CryptoUtilsException;

	/**
	 * Decrypts byte arrays using the specified key with RSA
	 * 
	 * @param cipherText
	 *            byte array to be decrypted
	 * @param encSessionKey
	 *            Encrypted Session Key used for encrypt the message with a
	 *            symmetric algorithm
	 * @param privateKey
	 *            Key to be used in the decryption process
	 * @param operationMode
	 *            Custom Operation mode (check out supported operationModes)
	 * @return Decrypted byte array
	 * @throws CryptoUtilsException
	 *             If something goes wrong
	 */
	byte[] decrypt(byte[] cipherText, byte[] encSessionKey,
			RSAPrivateKey privateKey, String operationMode)
			throws CryptoUtilsException;

	/**
	 * Decrypts byte arrays using the specified key with RSA using PKCS1 as
	 * default operation mode
	 * 
	 * @param cipherText
	 *            byte array to be decrypted
	 * @param encSessionKey
	 *            Encrypted Session Key used for encrypt the message with a
	 *            symmetric algorithm
	 * @param privateKey
	 *            Key to be used in the decryption process
	 * @return Decrypted byte array
	 * @throws CryptoUtilsException
	 *             If something goes wrong
	 */
	byte[] decrypt(byte[] cipherText, byte[] encSessionKey,
			RSAPrivateKey privateKey) throws CryptoUtilsException;

	/**
	 * Decrypts encoded text using the specified key with RSA default settings:
	 * none
	 * 
	 * @param cypherText
	 *            Text to be decrypted, must be encoded using the specified
	 *            coder
	 * @param encSessionKey
	 *            Encrypted Session Key used for encrypt the message with a
	 *            symmetric algorithm
	 * @param privateKey
	 *            Key to be used in the decryption process
	 * @param encoder
	 *            input Text encode format
	 * @param operationMode
	 *            Custom Operation mode (check out supported operationModes)
	 * @return Decrypted text encoded as UTF-8
	 * @throws CryptoUtilsException
	 *             If something goes wrong
	 */
	String decrypt(String cypherText, String encSessionKey,
			RSAPrivateKey privateKey, String encoder, String operationMode)
			throws CryptoUtilsException;

	/**
	 * Decrypts encoded text using the specified key with RSA default settings:
	 * PKCS1 operationMode
	 * 
	 * @param cypherText
	 *            Text to be decrypted, must be encoded using the specified
	 *            coder
	 * @param encSessionKey
	 *            Encrypted Session Key used for encrypt the message with a
	 *            symmetric algorithm
	 * @param privateKey
	 *            Key to be used in the decryption process
	 * @param encoder
	 *            input Text encode format
	 * @return Decrypted text encoded as UTF-8
	 * @throws CryptoUtilsException
	 *             If something goes wrong
	 */
	String decrypt(String cypherText, String encSessionKey,
			RSAPrivateKey privateKey, String encoder)
			throws CryptoUtilsException;

	/**
	 * Decrypts encoded text using the specified key with RSA default settings:
	 * PKCS1 operationMode, Base64 encoder
	 * 
	 * @param cypherText
	 *            Text to be decrypted, must be encoded using the specified
	 *            coder
	 * @param encSessionKey
	 *            Encrypted Session Key used for encrypt the message with a
	 *            symmetric algorithm
	 * @param privateKey
	 *            Key to be used in the decryption process
	 * @param encoder
	 *            input Text encode format
	 * @return Decrypted text encoded as UTF-8
	 * @throws CryptoUtilsException
	 *             If something goes wrong
	 */
	String decrypt(String cypherText, String encSessionKey,
			RSAPrivateKey privateKey) throws CryptoUtilsException;

	/**
	 * Generate the key pairs for RSA depending on the keySize specified (in
	 * bits)
	 * 
	 * @param keySizeInBits
	 *            Key Size must be in bits
	 * @return
	 */
	public RSAKeyPair generateKeys(int keySizeInBits)
			throws CryptoUtilsException;

	/**
	 * Generate ECKey pair in base of parameters like curve, field, order, etc
	 * 
	 * @param parameters
	 *            Parameters for the curve and the points
	 * @return A new EC Key Pair object
	 * @throws CryptoUtilsException
	 */
	public ECKeyPair generateKeys(ECDomainParameters parameters)
			throws CryptoUtilsException;

	/**
	 * Generate random ECKey pair for the selected nistCurve
	 * 
	 * @param nistCurveName
	 *            Name of the curve, as published in FIPS-PUB 186-2, see
	 *            ECDomainParameters for supported curves
	 * @return A new EC Key pair suited for the nist curve
	 */
	public ECKeyPair generateKeys(String nistCurveName)
			throws CryptoUtilsException;

	/**
	 * Sign a byte array that represents complete the message to be signed, this
	 * message will be hashed using the selected digest function and the result
	 * of this its what will be signed
	 * 
	 * @param message
	 *            Message to be signed
	 * @param privateKey
	 *            PrivateKey to be used for sign the message
	 * @param digestName
	 *            Digest function that will be used for hash the message (SHA-1
	 *            is the standard function for DSA), the supported functions are
	 *            in AndroidCryptoUtils class
	 * @return Two bigInteger array representing r and s respectively
	 * @throws CryptoUtilsException
	 *             if the digestFunction is not supported
	 */
	public BigInteger[] sign(byte[] message, ECPrivateKey privateKey,
			String digestName) throws CryptoUtilsException;

	/**
	 * Sign a byte array that represents complete the message to be signed, this
	 * message will be hashed using the selected digest function and the result
	 * of this its what will be signed
	 * 
	 * @param message
	 *            Message to be signed
	 * @param privateKey
	 *            PrivateKey to be used for sign the message
	 * @param digestName
	 *            Digest function that will be used for hash the message (SHA-1
	 *            is the standard function for DSA), the supported functions are
	 *            in AndroidCryptoUtils class
	 * @return Two bigInteger array representing r and s respectively
	 * @throws CryptoUtilsException
	 *             if the digestFunction is not supported
	 */
	public BigInteger[] sign(String message, ECPrivateKey privateKey,
			String digestName) throws CryptoUtilsException;

	/**
	 * Sign a byte array that represents complete the message to be signed, this
	 * message will be hashed using SHA-1 digest function and the result of this
	 * its what will be signed
	 * 
	 * @param message
	 *            Message to be signed
	 * @param privateKey
	 *            PrivateKey to be used for sign the message
	 * @return Two bigInteger array representing r and s respectively
	 * @throws CryptoUtilsException
	 *             if the digestFunction is not supported
	 */
	public BigInteger[] sign(byte[] message, ECPrivateKey privateKey)
			throws CryptoUtilsException;

	/**
	 * Sign a byte array that represents complete the message to be signed, this
	 * message will be hashed using SHA-1 digest function and the result of this
	 * its what will be signed
	 * 
	 * @param message
	 *            Message to be signed
	 * @param privateKey
	 *            PrivateKey to be used for sign the message
	 * @return Two bigInteger array representing r and s respectively
	 * @throws CryptoUtilsException
	 *             if the digestFunction is not supported
	 */
	public BigInteger[] sign(String message, ECPrivateKey privateKey)
			throws CryptoUtilsException;

	/**
	 * Verify the signature of a message, the input message will be hashed using
	 * the selected digest function and the result will be the input for the
	 * verify process
	 * 
	 * @param message
	 *            Original message which was signed
	 * @param sig
	 *            Sign of the message, should be a two BigInteger array with r
	 *            and s respectively
	 * @param publicKey
	 *            Public Key to be used for sign verification
	 * @param digestName
	 *            Digest function that will be used for hash the message (SHA-1
	 *            is the standard function for DSA), the supported functions are
	 *            in AndroidCryptoUtils class
	 * @return TRUE if the signature is correct, FALSE otherwise
	 * @throws CryptoUtilsException
	 *             if the signature is a valid ECDSA signature
	 */
	public Boolean verify(byte[] message, BigInteger[] sig,
			ECPublicKey publicKey, String digestName)
			throws CryptoUtilsException;

	/**
	 * Verify the signature of a message, the input message will be hashed using
	 * SHA-1 function and the result will be the input for the verify process
	 * 
	 * @param message
	 *            Original message which was signed
	 * @param sig
	 *            Sign of the message, should be a two BigInteger array with r
	 *            and s respectively
	 * @param publicKey
	 *            Public Key to be used for sign verification
	 * @return TRUE if the signature is correct, FALSE otherwise
	 * @throws CryptoUtilsException
	 *             if the signature is a valid ECDSA signature
	 */
	public Boolean verify(byte[] message, BigInteger[] sig,
			ECPublicKey publicKey) throws CryptoUtilsException;

	/**
	 * Verify the signature of a message, the input message will be hashed using
	 * the selected digest function and the result will be the input for the
	 * verify process
	 * 
	 * @param message
	 *            Original message which was signed
	 * @param sig
	 *            Sign of the message, should be a two BigInteger array with r
	 *            and s respectively
	 * @param publicKey
	 *            Public Key to be used for sign verification
	 * @param digestName
	 *            Digest function that will be used for hash the message (SHA-1
	 *            is the standard function for DSA), the supported functions are
	 *            in AndroidCryptoUtils class
	 * @return TRUE if the signature is correct, FALSE otherwise
	 * @throws CryptoUtilsException
	 *             if the signature is a valid ECDSA signature
	 */
	public Boolean verify(String message, BigInteger[] sig,
			ECPublicKey publicKey, String digestName)
			throws CryptoUtilsException;

	/**
	 * Verify the signature of a message, the input message will be hashed using
	 * SHA-1 function and the result will be the input for the verify process
	 * 
	 * @param message
	 *            Original message which was signed
	 * @param sig
	 *            Sign of the message, should be a two BigInteger array with r
	 *            and s respectively
	 * @param publicKey
	 *            Public Key to be used for sign verification
	 * @return TRUE if the signature is correct, FALSE otherwise
	 * @throws CryptoUtilsException
	 *             if the signature is a valid ECDSA signature
	 */
	public Boolean verify(String message, BigInteger[] sig,
			ECPublicKey publicKey) throws CryptoUtilsException;

	/**
	 * 
	 * Encrypts the input array using ECIES, this scheme offers beside
	 * encryption also authentication. Its important to mention that in this
	 * function AES-CBC will be used as BlockCipher scheme.
	 * 
	 * To encrypt the message, first a random session key is generated and used
	 * for encrypt the input message with a symmetric algorithm (AES-CBC),
	 * finally this key is encrypted with ECIES so this function return two
	 * things, the encrypted input message and the encrypted session key
	 * 
	 * @param input
	 *            Data to be encrypted
	 * @param receiverPartPublicKey
	 *            The EC public key of receiver,
	 * @param ownPrivateKey
	 *            EC Private key of the sender, for authentication proposes
	 * @param derivation
	 *            Derivation parameter array for the KDF algorithm used in the
	 *            IES scheme
	 * @param encoding
	 *            Encoding parameter array for the KDF algorithm used in the IES
	 *            scheme
	 * @param macSize
	 *            Size of the MAC key used by the IES Scheme
	 * @param keySize
	 *            Key Size for the cipher used by IES
	 * @return A List with 2 elements, first byte array representing the
	 *         encrypted message and secondly the encrypted session key, this
	 *         key was used for encrypt the input message with a symmetric
	 *         algorithm
	 * @throws CryptoUtilsException
	 */
	public List<byte[]> encrypt(byte[] input,
			ECPublicKey receiverPartPublicKey, ECPrivateKey ownPrivateKey,
			byte[] derivation, byte[] encoding, int macSize, int keySize)
			throws CryptoUtilsException;

	/**
	 * 
	 * Encrypts the input array using ECIES, this scheme offers beside
	 * encryption also authentication, using simple and default KDF parameters.
	 * Its important to mention that in this function AES-CBC will be used as
	 * BlockCipher scheme.
	 * 
	 * To encrypt the message, first a random session key is generated and used
	 * for encrypt the input message with a symmetric algorithm (AES-CBC),
	 * finally this key is encrypted with ECIES so this function return two
	 * things, the encrypted input message and the encrypted session key
	 * 
	 * @param input
	 *            Data to be encrypted
	 * @param receiverPartPublicKey
	 *            The EC public key of receiver,
	 * @param ownPrivateKey
	 *            EC Private key of the sender, for authentication proposes
	 * @param macSize
	 *            Size of the MAC key used by the IES Scheme
	 * @param keySize
	 *            Key Size for the cipher used by IES
	 * @return A List with 2 elements, first byte array representing the
	 *         encrypted message and secondly the encrypted session key, this
	 *         key was used for encrypt the input message with a symmetric
	 *         algorithm
	 * @throws CryptoUtilsException
	 */
	public List<byte[]> encrypt(byte[] input,
			ECPublicKey receiverPartPublicKey, ECPrivateKey ownPrivateKey,
			int macSize, int keySize) throws CryptoUtilsException;

	/**
	 * 
	 * Encrypts the input array using ECIES, this scheme offers beside
	 * encryption also authentication, using simple and default KDF parameters
	 * and a 64bit MAC key. Its important to mention that in this function
	 * AES-CBC will be used as BlockCipher scheme.
	 * 
	 * To encrypt the message, first a random session key is generated and used
	 * for encrypt the input message with a symmetric algorithm (AES-CBC),
	 * finally this key is encrypted with ECIES so this function return two
	 * things, the encrypted input message and the encrypted session key
	 * 
	 * @param input
	 *            Data to be encrypted
	 * @param receiverPartPublicKey
	 *            The EC public key of receiver,
	 * @param ownPrivateKey
	 *            EC Private key of the sender, for authentication proposes
	 * @param keySize
	 *            Key Size for the cipher used by IES
	 * @return A List with 2 elements, first byte array representing the
	 *         encrypted message and secondly the encrypted session key, this
	 *         key was used for encrypt the input message with a symmetric
	 *         algorithm
	 * @throws CryptoUtilsException
	 */
	public List<byte[]> encrypt(byte[] input,
			ECPublicKey receiverPartPublicKey, ECPrivateKey ownPrivateKey,
			int keySize) throws CryptoUtilsException;

	/**
	 * 
	 * Encrypts the input array using ECIES, this scheme offers beside
	 * encryption also authentication, using simple and default KDF parameters ,
	 * a 64bit MAC key and finally a 128 bit cipher key. Its important to
	 * mention that in this function AES-CBC will be used as BlockCipher scheme.
	 * 
	 * To encrypt the message, first a random session key is generated and used
	 * for encrypt the input message with a symmetric algorithm (AES-CBC),
	 * finally this key is encrypted with ECIES so this function return two
	 * things, the encrypted input message and the encrypted session key
	 * 
	 * @param input
	 *            Data to be encrypted
	 * @param receiverPartPublicKey
	 *            The EC public key of receiver,
	 * @param ownPrivateKey
	 *            EC Private key of the sender, for authentication proposes
	 * @param keySize
	 *            Key Size for the cipher used by IES
	 * @return A List with 2 elements, first byte array representing the
	 *         encrypted message and secondly the encrypted session key, this
	 *         key was used for encrypt the input message with a symmetric
	 *         algorithm
	 * @throws CryptoUtilsException
	 */
	public List<byte[]> encrypt(byte[] input,
			ECPublicKey receiverPartPublicKey, ECPrivateKey ownPrivateKey)
			throws CryptoUtilsException;

	/**
	 * Encrypts the input array using ECIES, this scheme offers beside
	 * encryption also authentication. Its important to mention that in this
	 * function AES-CBC will be used as BlockCipher scheme.
	 * 
	 * To encrypt the message, first a random session key is generated and used
	 * for encrypt the input message with a symmetric algorithm (AES-CBC),
	 * finally this key is encrypted with ECIES so this function return two
	 * things, the encrypted input message and the encrypted session key
	 * 
	 * @param input
	 *            Data to be encrypted (UTF-8 String)
	 * @param receiverPartPublicKey
	 *            The EC public key of receiver,
	 * @param ownPrivateKey
	 *            EC Private key of the sender, for authentication proposes
	 * @param derivation
	 *            Derivation parameter array for the KDF algorithm used in the
	 *            IES scheme
	 * @param encoding
	 *            Encoding parameter array for the KDF algorithm used in the IES
	 *            scheme
	 * @param macSize
	 *            Size of the MAC key used by the IES Scheme
	 * @param keySize
	 *            Key Size for the cipher used by IES
	 * @param encoder
	 *            Encoder(Base64 or HEX) to be used for the output of this
	 *            function
	 * @return A List with 2 elements, first byte array representing the
	 *         encrypted message and secondly the encrypted session key, this
	 *         key was used for encrypt the input message with a symmetric
	 *         algorithm
	 * @throws CryptoUtilsException
	 */
	public List<String> encrypt(String input,
			ECPublicKey receiverPartPublicKey, ECPrivateKey ownPrivateKey,
			byte[] derivation, byte[] encoding, int macSize, int keySize,
			String encoder) throws CryptoUtilsException;

	/**
	 * 
	 * Encrypts the input array using ECIES, this scheme offers beside
	 * encryption also authentication, using simple and default KDF parameters.
	 * Its important to mention that in this function AES-CBC will be used as
	 * BlockCipher scheme.
	 * 
	 * To encrypt the message, first a random session key is generated and used
	 * for encrypt the input message with a symmetric algorithm (AES-CBC),
	 * finally this key is encrypted with ECIES so this function return two
	 * things, the encrypted input message and the encrypted session key
	 * 
	 * @param input
	 *            Data to be encrypted(UTF-8 String)
	 * @param receiverPartPublicKey
	 *            The EC public key of receiver,
	 * @param ownPrivateKey
	 *            EC Private key of the sender, for authentication proposes
	 * @param macSize
	 *            Size of the MAC key used by the IES Scheme
	 * @param keySize
	 *            Key Size for the cipher used by IES
	 * @param encoder
	 *            Encoder(Base64 or HEX) to be used for the output of this
	 *            function
	 * @return A List with 2 elements, first byte array representing the
	 *         encrypted message and secondly the encrypted session key, this
	 *         key was used for encrypt the input message with a symmetric
	 *         algorithm
	 * @throws CryptoUtilsException
	 */
	public List<String> encrypt(String input,
			ECPublicKey receiverPartPublicKey, ECPrivateKey ownPrivateKey,
			int macSize, int keySize, String encoder)
			throws CryptoUtilsException;

	/**
	 * 
	 * Encrypts the input array using ECIES, this scheme offers beside
	 * encryption also authentication, using simple and default KDF parameters
	 * and a 64bit MAC key. Its important to mention that in this function
	 * AES-CBC will be used as BlockCipher scheme.
	 * 
	 * To encrypt the message, first a random session key is generated and used
	 * for encrypt the input message with a symmetric algorithm (AES-CBC),
	 * finally this key is encrypted with ECIES so this function return two
	 * things, the encrypted input message and the encrypted session key
	 * 
	 * @param input
	 *            Data to be encrypted(UTF-8 String)
	 * @param receiverPartPublicKey
	 *            The EC public key of receiver,
	 * @param ownPrivateKey
	 *            EC Private key of the sender, for authentication proposes
	 * @param keySize
	 *            Key Size for the cipher used by IES
	 * @param encoder
	 *            Encoder(Base64 or HEX) to be used for the output of this
	 *            function
	 * @return A List with 2 elements, first byte array representing the
	 *         encrypted message and secondly the encrypted session key, this
	 *         key was used for encrypt the input message with a symmetric
	 *         algorithm
	 * @throws CryptoUtilsException
	 */
	public List<String> encrypt(String input,
			ECPublicKey receiverPartPublicKey, ECPrivateKey ownPrivateKey,
			int keySize, String encoder) throws CryptoUtilsException;

	/**
	 * 
	 * Encrypts the input array using ECIES, this scheme offers beside
	 * encryption also authentication, using simple and default KDF parameters ,
	 * a 64bit MAC key and finally a 128 bit cipher key. Its important to
	 * mention that in this function AES-CBC will be used as BlockCipher scheme.
	 * 
	 * To encrypt the message, first a random session key is generated and used
	 * for encrypt the input message with a symmetric algorithm (AES-CBC),
	 * finally this key is encrypted with ECIES so this function return two
	 * things, the encrypted input message and the encrypted session key
	 * 
	 * @param input
	 *            Data to be encrypted(UTF-8 String)
	 * @param receiverPartPublicKey
	 *            The EC public key of receiver,
	 * @param ownPrivateKey
	 *            EC Private key of the sender, for authentication proposes
	 * @param keySize
	 *            Key Size for the cipher used by IES
	 * @param encoder
	 *            Encoder(Base64 or HEX) to be used for the output of this
	 *            function
	 * @return A List with 2 elements, first byte array representing the
	 *         encrypted message and secondly the encrypted session key, this
	 *         key was used for encrypt the input message with a symmetric
	 *         algorithm
	 * @throws CryptoUtilsException
	 */
	public List<String> encrypt(String input,
			ECPublicKey receiverPartPublicKey, ECPrivateKey ownPrivateKey,
			String encoder) throws CryptoUtilsException;

	/**
	 * 
	 * Encrypts the input array using ECIES, this scheme offers beside
	 * encryption also authentication, using simple and default KDF parameters ,
	 * a 64bit MAC key,a 128 bit cipher key, and finally base64 as default
	 * encoder. Its important to mention that in this function AES-CBC will be
	 * used as BlockCipher scheme.
	 * 
	 * To encrypt the message, first a random session key is generated and used
	 * for encrypt the input message with a symmetric algorithm (AES-CBC),
	 * finally this key is encrypted with ECIES so this function return two
	 * things, the encrypted input message and the encrypted session key
	 * 
	 * @param input
	 *            Data to be encrypted(UTF-8 String)
	 * @param receiverPartPublicKey
	 *            The EC public key of receiver,
	 * @param ownPrivateKey
	 *            EC Private key of the sender, for authentication proposes
	 * @param keySize
	 *            Key Size for the cipher used by IES
	 * @return A List with 2 elements, first byte array representing the
	 *         encrypted message and secondly the encrypted session key, this
	 *         key was used for encrypt the input message with a symmetric
	 *         algorithm
	 * @throws CryptoUtilsException
	 */
	public List<String> encrypt(String input,
			ECPublicKey receiverPartPublicKey, ECPrivateKey ownPrivateKey)
			throws CryptoUtilsException;

	/**
	 * 
	 * Decrypts the input array using ECIES, this scheme offers beside
	 * encryption also authentication. Its important to mention that in this
	 * function AES-CBC will be used as BlockCipher scheme
	 * 
	 * In order to decrypt the message, first the session key must be decrypted
	 * using ECIES, then using the decrypted session key the message is
	 * decrypted and this is the result for this function
	 * 
	 * @param input
	 *            Data to be decrypted
	 * @param encSessionKey
	 *            Encrypted session key used for encrypt the original message
	 *            using a symmetric algorithm
	 * @param senderPartPublicKey
	 *            The EC public key of sender,
	 * @param ownPrivateKey
	 *            Our EC Private Key, for authentication proposes
	 * @param derivation
	 *            Derivation parameter array for the KDF algorithm used in the
	 *            IES scheme
	 * @param encoding
	 *            Encoding parameter array for the KDF algorithm used in the IES
	 *            scheme
	 * @param macSize
	 *            Size of the MAC key used by the IES Scheme
	 * @param keySize
	 *            Key Size for the cipher used by IES
	 * @return byte array representing the decrypted message
	 * @throws CryptoUtilsException
	 */
	public byte[] decrypt(byte[] input, byte[] encSessionKey,
			ECPublicKey senderPartPublicKey, ECPrivateKey ownPrivateKey,
			byte[] derivation, byte[] encoding, int macSize, int keySize)
			throws CryptoUtilsException;

	/**
	 * 
	 * Decrypts the input array using ECIES, this scheme offers beside
	 * encryption also authentication, using simple and default KDF parameters.
	 * Its important to mention that in this function AES-CBC will be used as
	 * BlockCipher scheme
	 * 
	 * In order to decrypt the message, first the session key must be decrypted
	 * using ECIES, then using the decrypted session key the message is
	 * decrypted and this is the result for this function
	 * 
	 * @param input
	 *            Data to be decrypted
	 * @param encSessionKey
	 *            Encrypted Session Key used for encrypt the message with a
	 *            symmetric algorithm
	 * @param senderPartPublicKey
	 *            The EC public key of sender,
	 * @param ownPrivateKey
	 *            Our EC Private Key, for authentication proposes
	 * @param macSize
	 *            Size of the MAC key used by the IES Scheme
	 * @param keySize
	 *            Key Size for the cipher used by IES
	 * @return byte array representing the decrypted message
	 * @throws CryptoUtilsException
	 */
	public byte[] decrypt(byte[] input, byte[] encSessionKey,
			ECPublicKey senderPartPublicKey, ECPrivateKey ownPrivateKey,
			int macSize, int keySize) throws CryptoUtilsException;

	/**
	 * 
	 * Decrypts the input array using ECIES, this scheme offers beside
	 * encryption also authentication.,using simple and default KDF parameters ,
	 * and 64bit MAC key. Its important to mention that in this function AES-CBC
	 * will be used as BlockCipher scheme
	 * 
	 * In order to decrypt the message, first the session key must be decrypted
	 * using ECIES, then using the decrypted session key the message is
	 * decrypted and this is the result for this function
	 * 
	 * @param input
	 *            Data to be decrypted
	 * @param encSessionKey
	 *            Encrypted Session Key used for encrypt the message with a
	 *            symmetric algorithm
	 * @param senderPartPublicKey
	 *            The EC public key of sender,
	 * @param ownPrivateKey
	 *            Our EC Private Key, for authentication proposes
	 * @param keySize
	 *            Key Size for the cipher used by IES
	 * @return byte array representing the decrypted message
	 * @throws CryptoUtilsException
	 */
	public byte[] decrypt(byte[] input, byte[] encSessionKey,
			ECPublicKey senderPartPublicKey, ECPrivateKey ownPrivateKey,
			int keySize) throws CryptoUtilsException;

	/**
	 * 
	 * Decrypts the input array using ECIES, this scheme offers beside
	 * encryption also authentication, using simple and default KDF parameters ,
	 * a 64bit MAC key and finally a 128 bit cipher key. Its important to
	 * mention that in this function AES-CBC will be used as BlockCipher scheme
	 * 
	 * In order to decrypt the message, first the session key must be decrypted
	 * using ECIES, then using the decrypted session key the message is
	 * decrypted and this is the result for this function
	 * 
	 * @param input
	 *            Data to be decrypted
	 * @param encSessionKey
	 *            Encrypted Session Key used for encrypt the message with a
	 *            symmetric algorithm
	 * @param senderPartPublicKey
	 *            The EC public key of sender,
	 * @param ownPrivateKey
	 *            Our EC Private Key, for authentication proposes
	 * @return byte array representing the decrypted message
	 * @throws CryptoUtilsException
	 */
	public byte[] decrypt(byte[] input, byte[] encSessionKey,
			ECPublicKey senderPartPublicKey, ECPrivateKey ownPrivateKey)
			throws CryptoUtilsException;

	/**
	 * 
	 * Decrypts the input array using ECIES, this scheme offers beside
	 * encryption also authentication. Its important to mention that in this
	 * function AES-CBC will be used as BlockCipher scheme
	 * 
	 * In order to decrypt the message, first the session key must be decrypted
	 * using ECIES, then using the decrypted session key the message is
	 * decrypted and this is the result for this function
	 * 
	 * @param input
	 *            Data to be decrypted
	 * @param encSessionKey
	 *            Encrypted session key used for encrypt the original message
	 *            using a symmetric algorithm
	 * @param senderPartPublicKey
	 *            The EC public key of sender,
	 * @param ownPrivateKey
	 *            Our EC Private Key, for authentication proposes
	 * @param derivation
	 *            Derivation parameter array for the KDF algorithm used in the
	 *            IES scheme
	 * @param encoding
	 *            Encoding parameter array for the KDF algorithm used in the IES
	 *            scheme
	 * @param macSize
	 *            Size of the MAC key used by the IES Scheme
	 * @param keySize
	 *            Key Size for the cipher used by IES
	 * @param encoder
	 *            Name of the encoder (Base64 or HEX) to be used in the inputs
	 *            of this function
	 * @return byte array representing the decrypted message
	 * @throws CryptoUtilsException
	 */
	public String decrypt(String input, String encSessionKey,
			ECPublicKey senderPartPublicKey, ECPrivateKey ownPrivateKey,
			byte[] derivation, byte[] encoding, int macSize, int keySize,
			String encoder) throws CryptoUtilsException;

	/**
	 * 
	 * Decrypts the input array using ECIES, this scheme offers beside
	 * encryption also authentication, using simple and default KDF parameters.
	 * Its important to mention that in this function AES-CBC will be used as
	 * BlockCipher scheme
	 * 
	 * In order to decrypt the message, first the session key must be decrypted
	 * using ECIES, then using the decrypted session key the message is
	 * decrypted and this is the result for this function
	 * 
	 * @param input
	 *            Data to be decrypted
	 * @param encSessionKey
	 *            Encrypted Session Key used for encrypt the message with a
	 *            symmetric algorithm
	 * @param senderPartPublicKey
	 *            The EC public key of sender,
	 * @param ownPrivateKey
	 *            Our EC Private Key, for authentication proposes
	 * @param macSize
	 *            Size of the MAC key used by the IES Scheme
	 * @param keySize
	 *            Key Size for the cipher used by IES
	 * @param encoder
	 *            Name of the encoder (Base64 or HEX) to be used in the inputs
	 *            of this function
	 * @return byte array representing the decrypted message
	 * @throws CryptoUtilsException
	 */
	public String decrypt(String input, String encSessionKey,
			ECPublicKey senderPartPublicKey, ECPrivateKey ownPrivateKey,
			int macSize, int keySize, String encoder)
			throws CryptoUtilsException;

	/**
	 * 
	 * Decrypts the input array using ECIES, this scheme offers beside
	 * encryption also authentication.,using simple and default KDF parameters ,
	 * and 64bit MAC key. Its important to mention that in this function AES-CBC
	 * will be used as BlockCipher scheme
	 * 
	 * In order to decrypt the message, first the session key must be decrypted
	 * using ECIES, then using the decrypted session key the message is
	 * decrypted and this is the result for this function
	 * 
	 * @param input
	 *            Data to be decrypted
	 * @param encSessionKey
	 *            Encrypted Session Key used for encrypt the message with a
	 *            symmetric algorithm
	 * @param senderPartPublicKey
	 *            The EC public key of sender,
	 * @param ownPrivateKey
	 *            Our EC Private Key, for authentication proposes
	 * @param keySize
	 *            Key Size for the cipher used by IES
	 * @param encoder
	 *            Name of the encoder (Base64 or HEX) to be used in the inputs
	 *            of this function
	 * @return byte array representing the decrypted message
	 * @throws CryptoUtilsException
	 */
	public String decrypt(String input, String encSessionKey,
			ECPublicKey senderPartPublicKey, ECPrivateKey ownPrivateKey,
			int keySize, String encoder) throws CryptoUtilsException;

	/**
	 * 
	 * Decrypts the input array using ECIES, this scheme offers beside
	 * encryption also authentication, using simple and default KDF parameters ,
	 * a 64bit MAC key and finally a 128 bit cipher key. Its important to
	 * mention that in this function AES-CBC will be used as BlockCipher scheme
	 * 
	 * In order to decrypt the message, first the session key must be decrypted
	 * using ECIES, then using the decrypted session key the message is
	 * decrypted and this is the result for this function
	 * 
	 * @param input
	 *            Data to be decrypted
	 * @param encSessionKey
	 *            Encrypted Session Key used for encrypt the message with a
	 *            symmetric algorithm
	 * @param senderPartPublicKey
	 *            The EC public key of sender,
	 * @param ownPrivateKey
	 *            Our EC Private Key, for authentication proposes
	 * @param encoder
	 *            Name of the encoder (Base64 or HEX) to be used in the inputs
	 *            of this function
	 * @return byte array representing the decrypted message
	 * @throws CryptoUtilsException
	 */
	public String decrypt(String input, String encSessionKey,
			ECPublicKey senderPartPublicKey, ECPrivateKey ownPrivateKey,
			String encoder) throws CryptoUtilsException;

	/**
	 * 
	 * Decrypts the input array using ECIES, this scheme offers beside
	 * encryption also authentication, using simple and default KDF parameters ,
	 * a 64bit MAC key and finally a 128 bit cipher key. Its important to
	 * mention that in this function AES-CBC will be used as BlockCipher scheme
	 * 
	 * In order to decrypt the message, first the session key must be decrypted
	 * using ECIES, then using the decrypted session key the message is
	 * decrypted and this is the result for this function
	 * 
	 * @param input
	 *            Data to be decrypted
	 * @param encSessionKey
	 *            Encrypted Session Key used for encrypt the message with a
	 *            symmetric algorithm
	 * @param senderPartPublicKey
	 *            The EC public key of sender,
	 * @param ownPrivateKey
	 *            Our EC Private Key, for authentication proposes
	 * @return byte array representing the decrypted message
	 * @throws CryptoUtilsException
	 */
	public String decrypt(String input, String encSessionKey,
			ECPublicKey senderPartPublicKey, ECPrivateKey ownPrivateKey)
			throws CryptoUtilsException;

}
