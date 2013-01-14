/**
 *  Created on  : 15/03/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description : 
 *  	Public interface for Android Symmetric CryptoUtils Class, 
 *  	will contain basic symmetric cryptography functions
 *  	
 */
package cinvestav.android.pki.cryptography.utils;

import java.io.IOException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;

import javax.crypto.SecretKey;

import cinvestav.android.pki.cryptography.exception.CryptoUtilsException;

/**
 * @author Ing. Javier Silva Pérez - [javier]
 * 
 */
public interface ISymmetricCryptoUtils {

	/**
	 * Encrypts encoded text using the specified key with AES-[KeySize] Uses the
	 * following default settings: AES128, PKCS7 padding, CBC as operation mode,
	 * empty IV, Base64 Coder
	 * 
	 * @param plainText
	 *            Text to be encrypted, must be UTF-8 text
	 * @param key
	 *            Key to be used in the encryption process
	 * @return Encrypted text encoded using the specified coder
	 * @throws CryptoUtilsException
	 *             If something goes wrong
	 */
	String aes_encrypt(String plainText, byte[] key)
			throws CryptoUtilsException;

	/**
	 * Encrypts encoded text using the specified key with AES-[KeySize] Uses the
	 * following default settings: PKCS7 padding, CBC as operation mode, empty
	 * IV, Base64 Coder
	 * 
	 * @param keySize
	 *            AES key size to use [128,192,256]
	 * @param plainText
	 *            Text to be encrypted, must be UTF-8 text
	 * @param key
	 *            Key to be used in the encryption process
	 * @return Encrypted text encoded using the specified coder
	 * @throws CryptoUtilsException
	 *             If something goes wrong
	 */
	String aes_encrypt(Integer keySize, String plainText, byte[] key)
			throws CryptoUtilsException;

	/**
	 * Encrypts encoded text using the specified key with AES-[KeySize] Uses
	 * PKCS7 padding, CBC as operation mode and empty IV by default
	 * 
	 * @param keySize
	 *            AES key size to use [128,192,256]
	 * @param coder
	 *            output Text encode format
	 * @param plainText
	 *            Text to be encrypted, must be UTF-8 text
	 * @param key
	 *            Key to be used in the encryption process
	 * @return Encrypted text encoded using the specified coder
	 * @throws CryptoUtilsException
	 *             If something goes wrong
	 */
	String aes_encrypt(Integer keySize, String coder, String plainText,
			byte[] key) throws CryptoUtilsException;

	/**
	 * Encrypts encoded text using the specified key with AES-[KeySize] Uses
	 * PKCS7 padding and CBC as operation mode by default
	 * 
	 * @param keySize
	 *            AES key size to use [128,192,256]
	 * @param coder
	 *            output Text encode format
	 * @param plainText
	 *            Text to be encrypted, must be UTF-8 text
	 * @param key
	 *            Key to be used in the encryption process
	 * @param iv
	 *            Initialization Vector to be used
	 * @return Encrypted text encoded using the specified coder
	 * @throws CryptoUtilsException
	 *             If something goes wrong
	 */
	String aes_encrypt(Integer keySize, String coder, String plainText,
			byte[] key, byte[] iv) throws CryptoUtilsException;

	/**
	 * Encrypts encoded text using the specified key with AES-[KeySize] Uses
	 * PKCS7 padding by default
	 * 
	 * @param keySize
	 *            AES key size to throws AndroidCryptoUtilsExceptionuse
	 *            [128,192,256]
	 * @param coder
	 *            output Text encode format
	 * @param plainText
	 *            Text to be encrypted, must be UTF-8 text
	 * @param key
	 *            Key to be used in the encryption process
	 * @param iv
	 *            Initialization Vector to be used
	 * @param operationMode
	 *            Custom Operation mode (check out supported operationModes)
	 * @return Encrypted text encoded using the specified coder
	 * @throws CryptoUtilsException
	 *             If something goes wrong
	 */
	String aes_encrypt(Integer keySize, String coder, String plainText,
			byte[] key, byte[] iv, String operationMode)
			throws CryptoUtilsException;

	/**
	 * Encrypts encoded text using the specified key with AES-[KeySize]
	 * 
	 * @param keySize
	 *            AES key size to use [128,192,256]
	 * @param coder
	 *            output Text encode format
	 * @param plainText
	 *            Text to be encrypted, must be UTF-8 text
	 * @param key
	 *            Key to be used in the encryption process
	 * @param iv
	 *            Initialization Vector to be used
	 * @param operationMode
	 *            Custom Operation mode (check out supported operationModes)
	 * @param paddingStyle
	 *            Custom padding Style (check out supported paddings)
	 * @return Encrypted text encoded using the specified coder
	 * @throws CryptoUtilsException
	 *             If something goes wrong
	 */
	String aes_encrypt(Integer keySize, String coder, String plainText,
			byte[] key, byte[] iv, String operationMode, String paddingStyle)
			throws CryptoUtilsException;

	/**
	 * Encrypts byte arrays using the specified key with AES-[KeySize] default
	 * settings: AES128, PKCS7 padding, CBC operation mode, empty iv
	 * 
	 * @param plainText
	 *            byte array to be encrypted
	 * @param key
	 *            Key to be used in the encryption process
	 * @return Encrypted byte array
	 * @throws CryptoUtilsException
	 *             If something goes wrong
	 */
	byte[] aes_encrypt(byte[] plainText, byte[] key)
			throws CryptoUtilsException;

	/**
	 * Encrypts byte arrays using the specified key with AES-[KeySize] default
	 * settings: PKCS7 padding, CBC operation mode, empty iv
	 * 
	 * @param keySize
	 *            AES key size to use [128,192,256]
	 * @param plainText
	 *            byte array to be encrypted
	 * @param key
	 *            Key to be used in the encryption process
	 * @return Encrypted byte array
	 * @throws CryptoUtilsException
	 *             If something goes wrong
	 */
	byte[] aes_encrypt(Integer keySize, byte[] plainText, byte[] key)
			throws CryptoUtilsException;

	/**
	 * Encrypts byte arrays using the specified key with AES-[KeySize] default
	 * settings: PKCS7 padding, CBC operation mode
	 * 
	 * @param keySize
	 *            AES key size to use [128,192,256]
	 * @param plainText
	 *            byte array to be encrypted
	 * @param key
	 *            Key to be used in the encryption process
	 * @param iv
	 *            Initialization Vector to be used
	 * @return Encrypted byte array
	 * @throws CryptoUtilsException
	 *             If something goes wrong
	 */
	byte[] aes_encrypt(Integer keySize, byte[] plainText, byte[] key, byte[] iv)
			throws CryptoUtilsException;

	/**
	 * Encrypts byte arrays using the specified key with AES-[KeySize] default
	 * settings: PKCS7 padding
	 * 
	 * @param keySize
	 *            AES key size to use [128,192,256]
	 * @param plainText
	 *            byte array to be encrypted
	 * @param key
	 *            Key to be used in the encryption process
	 * @param iv
	 *            Initialization Vector to be used
	 * @param operationMode
	 *            Custom Operation mode (check out supported operationModes)
	 * @return Encrypted byte array
	 * @throws CryptoUtilsException
	 *             If something goes wrong
	 */
	byte[] aes_encrypt(Integer keySize, byte[] plainText, byte[] key, byte[] iv,
			String operationMode) throws CryptoUtilsException;

	/**
	 * Encrypts byte arrays using the specified key with AES-[KeySize]
	 * 
	 * @param keySize
	 *            AES key size to use [128,192,256]
	 * @param plainText
	 *            byte array to be encrypted
	 * @param key
	 *            Key to be used in the encryption process
	 * @param iv
	 *            Initialization Vector to be used
	 * @param operationMode
	 *            Custom Operation mode (check out supported operationModes)
	 * @param paddingStyle
	 *            Custom padding Style (check out supported paddings)
	 * @return Encrypted byte array
	 * @throws CryptoUtilsException
	 *             If something goes wrong
	 */
	byte[] aes_encrypt(Integer keySize, byte[] plainText, byte[] key, byte[] iv,
			String operationMode, String paddingStyle)
			throws CryptoUtilsException;

	/**
	 * Decrypts encoded text using the specified key with AES-[KeySize] default
	 * settings: AES128, Base64 Coder, PKCS7 padding, CBC operation Mode, empty
	 * IV
	 * 
	 * @param plainText
	 *            Text to be decrypted, must be encoded using the specified
	 *            coder
	 * @param key
	 *            Key to be used in the decryption process
	 * @return Decrypted text encoded as UTF-8
	 * @throws CryptoUtilsException
	 *             If something goes wrong
	 */
	String aes_decrypt(String cypherText, byte[] key)
			throws CryptoUtilsException;

	/**
	 * Decrypts encoded text using the specified key with AES-[KeySize] default
	 * settings: Base64 Coder, PKCS7 padding, CBC operation Mode, empty IV
	 * 
	 * @param keySize
	 *            AES key size to use [128,192,256]
	 * @param plainText
	 *            Text to be decrypted, must be encoded using the specified
	 *            coder
	 * @param key
	 *            Key to be used in the decryption process
	 * @return Decrypted text encoded as UTF-8
	 * @throws CryptoUtilsException
	 *             If something goes wrong
	 */
	String aes_decrypt(Integer keySize, String cypherText, byte[] key)
			throws CryptoUtilsException;

	/**
	 * Decrypts encoded text using the specified key with AES-[KeySize] default
	 * settings: PKCS7 padding, CBC operation Mode, empty IV
	 * 
	 * @param keySize
	 *            AES key size to use [128,192,256]
	 * @param coder
	 *            input Text encode format
	 * @param plainText
	 *            Text to be decrypted, must be encoded using the specified
	 *            coder
	 * @param key
	 *            Key to be used in the decryption process
	 * @return Decrypted text encoded as UTF-8
	 * @throws CryptoUtilsException
	 *             If something goes wrong
	 */
	String aes_decrypt(Integer keySize, String coder, String cypherText,
			byte[] key) throws CryptoUtilsException;

	/**
	 * Decrypts encoded text using the specified key with AES-[KeySize] default
	 * settings: PKCS7 padding, CBC operation Mode
	 * 
	 * @param keySize
	 *            AES key size to use [128,192,256]
	 * @param coder
	 *            input Text encode format
	 * @param plainText
	 *            Text to be decrypted, must be encoded using the specified
	 *            coder
	 * @param key
	 *            Key to be used in the decryption process
	 * @param iv
	 *            Initialization Vector to be used
	 * @return Decrypted text encoded as UTF-8
	 * @throws CryptoUtilsException
	 *             If something goes wrong
	 */
	String aes_decrypt(Integer keySize, String coder, String cypherText,
			byte[] key, byte[] iv) throws CryptoUtilsException;

	/**
	 * Decrypts encoded text using the specified key with AES-[KeySize] default
	 * settings: PKCS7 padding
	 * 
	 * @param keySize
	 *            AES key size to use [128,192,256]
	 * @param coder
	 *            input Text encode format
	 * @param plainText
	 *            Text to be decrypted, must be encoded using the specified
	 *            coder
	 * @param key
	 *            Key to be used in the decryption process
	 * @param iv
	 *            Initialization Vector to be used
	 * @param operationMode
	 *            Custom Operation mode (check out supported operationModes)
	 * @return Decrypted text encoded as UTF-8
	 * @throws CryptoUtilsException
	 *             If something goes wrong
	 */
	String aes_decrypt(Integer keySize, String coder, String cypherText,
			byte[] key, byte[] iv, String operationMode)
			throws CryptoUtilsException;

	/**
	 * Decrypts encoded text using the specified key with AES-[KeySize] default
	 * settings: none
	 * 
	 * @param keySize
	 *            AES key size to use [128,192,256]
	 * @param coder
	 *            input Text encode format
	 * @param plainText
	 *            Text to be decrypted, must be encoded using the specified
	 *            coder
	 * @param key
	 *            Key to be used in the decryption process
	 * @param iv
	 *            Initialization Vector to be used
	 * @param operationMode
	 *            Custom Operation mode (check out supported operationModes)
	 * @param paddingStyle
	 *            Custom padding Style (check out supported paddings)
	 * @return Decrypted text encoded as UTF-8
	 * @throws CryptoUtilsException
	 *             If something goes wrong
	 */
	String aes_decrypt(Integer keySize, String coder, String cypherText,
			byte[] key, byte[] iv, String operationMode, String paddingStyle)
			throws CryptoUtilsException;

	/**
	 * Decrypts byte arrays using the specified key with AES-[KeySize] default
	 * settings: AES128, PKCS7 padding, CBC operation mode, empty IV
	 * 
	 * @param cypherText
	 *            byte array to be decrypted
	 * @param key
	 *            Key to be used in the decryption process
	 * @return Decrypted byte array
	 * @throws CryptoUtilsException
	 *             If something goes wrong
	 */
	byte[] aes_decrypt(byte[] cypherText, byte[] key)
			throws CryptoUtilsException;

	/**
	 * Decrypts byte arrays using the specified key with AES-[KeySize] default
	 * settings: PKCS7 padding, CBC operation mode, empty IV
	 * 
	 * @param keySize
	 *            AES key size to use [128,192,256]
	 * @param cypherText
	 *            byte array to be decrypted
	 * @param key
	 *            Key to be used in the decryption process
	 * @return Decrypted byte array
	 * @throws CryptoUtilsException
	 *             If something goes wrong
	 */
	byte[] aes_decrypt(Integer keySize, byte[] cypherText, byte[] key)
			throws CryptoUtilsException;

	/**
	 * Decrypts byte arrays using the specified key with AES-[KeySize] default
	 * settings: PKCS7 padding, CBC operation mode
	 * 
	 * @param keySize
	 *            AES key size to use [128,192,256]
	 * @param cypherText
	 *            byte array to be decrypted
	 * @param key
	 *            Key to be used in the decryption process
	 * @param iv
	 *            Initialization Vector to be used
	 * @return Decrypted byte array
	 * @throws CryptoUtilsException
	 *             If something goes wrong
	 */
	byte[] aes_decrypt(Integer keySize, byte[] cypherText, byte[] key, byte[] iv)
			throws CryptoUtilsException;

	/**
	 * Decrypts byte arrays using the specified key with AES-[KeySize] default
	 * settings: PKCS7 padding
	 * 
	 * @param keySize
	 *            AES key size to use [128,192,256]
	 * @param cypherText
	 *            byte array to be decrypted
	 * @param key
	 *            Key to be used in the decryption process
	 * @param iv
	 *            Initialization Vector to be used
	 * @param operationMode
	 *            Custom Operation mode (check out supported operationModes)
	 * @return Decrypted byte array
	 * @throws CryptoUtilsException
	 *             If something goes wrong
	 */
	byte[] aes_decrypt(Integer keySize, byte[] cypherText, byte[] key,
			byte[] iv, String operationMode) throws CryptoUtilsException;

	/**
	 * Decrypts byte arrays using the specified key with AES-[KeySize]
	 * 
	 * @param keySize
	 *            AES key size to use [128,192,256]
	 * @param cypherText
	 *            byte array to be decrypted
	 * @param key
	 *            Key to be used in the decryption process
	 * @param iv
	 *            Initialization Vector to be used
	 * @param operationMode
	 *            Custom Operation mode (check out supported operationModes)
	 * @param paddingStyle
	 *            Custom padding Style (check out supported paddings)
	 * @return Decrypted byte array
	 * @throws CryptoUtilsException
	 *             If something goes wrong
	 */
	byte[] aes_decrypt(Integer keySize, byte[] cypherText, byte[] key,
			byte[] iv, String operationMode, String paddingStyle)
			throws CryptoUtilsException;

	/**
	 * Creates a new AES key depending on the preferred keySize
	 * 
	 * @param keySize
	 *            Should 128, 192 or 256
	 * @return Byte array containing the generated key
	 */
	byte[] aes_generateKey(Integer keySize) throws CryptoUtilsException;

	/**
	 * Gets the Key from the input File
	 * 
	 * @param keyFileName
	 *            Name of File in which the key is stored
	 * @return The key readed from the file
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 */
	public byte[] aes_getKey(String keyFileName)
			throws CryptoUtilsException;

	/**
	 * Gets AES key from a KeyStore
	 * 
	 * @param keyStoreFileName
	 *            Name of the file in which the KeyStore is saved
	 * @param keyStorePassword
	 *            Password for the KeyStore
	 * @param keyAlias
	 *            KeyAlias
	 * @param keyPassword
	 *            Password for the Key stored in the KeyStore
	 * @return The Key loaded from the keyStore
	 * @throws CryptoUtilsException
	 *             If an error occurs during the key load this error MUST be
	 *             handled
	 */
	public byte[] aes_getKey(KeyStore ks, String keyAlias, String keyPassword)
			throws CryptoUtilsException;
	
	public SecretKey aes_getSecretKey(byte[] key) throws CryptoUtilsException;

	/**
	 * Add the key to the KeyStore
	 * 
	 * @param ks
	 *            KeyStore in which the key will be added, this KeyStore must be
	 *            complety loaded
	 * @param key
	 *            SecretKey to store
	 * @param alias
	 *            Alias to store the key
	 * @param keyPassword
	 *            Password to protect the secretKey in the keystore
	 * @throws CryptoUtilsException
	 */
	public void aes_addKeyToKeyStore(KeyStore ks, SecretKey key, String alias,
			String keyPassword) throws CryptoUtilsException;

	/**
	 * Saves the key to a file
	 * 
	 * @param fileFullName
	 *            File name (Including Path and extension) in which the key will
	 *            be stored
	 * @throws CryptoUtilsException
	 */
	void aes_saveKeyToFile(byte[] key, String fileFullName)
			throws CryptoUtilsException;
}
