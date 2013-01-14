/**
 *  Created on  : 23/03/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	This  class implements the common functions for AES like encrypt, decrypt, keyGen
 *     	using the SouncyCastle API (http://rtyley.github.com/spongycastle/)
 *  	
 */
package cinvestav.android.pki.cryptography.algorithm;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableKeyException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.spongycastle.crypto.BlockCipher;
import org.spongycastle.crypto.BufferedBlockCipher;
import org.spongycastle.crypto.CryptoException;
import org.spongycastle.crypto.DataLengthException;
import org.spongycastle.crypto.engines.AESEngine;
import org.spongycastle.crypto.modes.CBCBlockCipher;
import org.spongycastle.crypto.modes.CFBBlockCipher;
import org.spongycastle.crypto.modes.OFBBlockCipher;
import org.spongycastle.crypto.modes.OpenPGPCFBBlockCipher;
import org.spongycastle.crypto.modes.PGPCFBBlockCipher;
import org.spongycastle.crypto.paddings.BlockCipherPadding;
import org.spongycastle.crypto.paddings.ISO10126d2Padding;
import org.spongycastle.crypto.paddings.ISO7816d4Padding;
import org.spongycastle.crypto.paddings.PKCS7Padding;
import org.spongycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.spongycastle.crypto.paddings.X923Padding;
import org.spongycastle.crypto.paddings.ZeroBytePadding;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.crypto.params.ParametersWithIV;
import org.spongycastle.jce.provider.BouncyCastleProvider;

import cinvestav.android.pki.cryptography.exception.CryptoUtilsException;
import cinvestav.android.pki.cryptography.utils.CryptoUtils;

/**
 * @author Ing. Javier Silva Pérez - [javier]
 * 
 */
public class AES {
	
	static {
		Security.addProvider(new BouncyCastleProvider());
	}
	/**
	 * Supported Operation modes types
	 */
	public static final String OPERATION_MODE_CBC = "CBC";
	public static final String OPERATION_MODE_CFB = "CFB";
	public static final String OPERATION_MODE_OFB = "OFB";
	public static final String OPERATION_MODE_OPENPGP = "OPENPGP";
	public static final String OPERATION_MODE_PGP = "PGP";

	/**
	 * Supported Padding types
	 */
	public static final String PADDING_TYPE_PKCS7 = "PKCS7";
	public static final String PADDING_TYPE_ISO10126d2 = "ISO10126d2";
	public static final String PADDING_TYPE_ISO7816d4 = "ISO7816d4";
	public static final String PADDING_TYPE_X932 = "X932";
	public static final String PADDING_TYPE_ZEROBYTE = "ZEROBYTE";
	public static final String PADDING_TYPE_NO_PADDING = "NO_PADDING";

	private Integer _keySize;
	private SecureRandom secureRandom;

	/**
	 * Default Constructor, sets the AES KeySize to 128
	 */
	public AES() {
		_keySize = 128;
		secureRandom = new SecureRandom();
	}

	/**
	 * Constructor, sets the keySize to the AES algorithm
	 * 
	 * @param keySize
	 *            Size of the Key to use in the algotithm [128,192,256]
	 * @throws CryptoUtilsException
	 *             If the key Size is different from [128,192,256]
	 */
	public AES(Integer keySize) throws CryptoUtilsException {
		this.setKeySize(keySize);
		secureRandom = new SecureRandom();
	}

	/**
	 * Gets the KeySize used in the algorithm
	 * 
	 * @return the keySize
	 */
	public Integer getKeySize() {
		return _keySize;
	}

	/**
	 * Sets the value of the key size to use
	 * 
	 * @param keySize
	 *            Size of the Key to use in the algotithm [128,192,256]
	 * @throws CryptoUtilsException
	 *             If the key Size is different from [128,192,256]
	 */
	public void setKeySize(Integer keySize) throws CryptoUtilsException {
		if (keySize == 128 || keySize == 192 || keySize == 256)
			this._keySize = keySize;
		else
			throw new CryptoUtilsException(
					"The key size must be 128,192 or 256");
	}

	/**
	 * Creates a new Key in order of the KeySize
	 * 
	 * @return a new AES-Key
	 * @throws NoSuchAlgorithmException
	 */
	public SecretKey createSecretKey() throws CryptoUtilsException {
		SecretKey key = null;
		KeyGenerator kgen;
		try {
			kgen = KeyGenerator.getInstance("AES", CryptoUtils.PROVIDER);
			kgen.init(this._keySize);
			key = kgen.generateKey();
			return key;
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			throw new CryptoUtilsException("[createSecretKey] :" + e,
					e);
		} catch (NoSuchAlgorithmException ex) {
			throw new CryptoUtilsException("[createSecretKey] :" + ex,
					ex);
		}
	}

	/**
	 * Creates a new SecretKey from a byte array containing the corresponding
	 * Key
	 * 
	 * @param key
	 *            byte array containing the key
	 * @return a new AES-Key
	 * @throws NoSuchAlgorithmException
	 */
	public SecretKey createSecretKey(byte[] key)
			throws CryptoUtilsException {
		SecretKey skey = null;
		skey = new SecretKeySpec(key, 0, key.length, "AES");
		return skey;
	}

	/**
	 * Creates a new Key contained in ParametersWithRandom class, the key size
	 * depends on the class attribute named keysize
	 * 
	 * @param secureRandom
	 *            Instance of SecureRandom Class, must be not null
	 * @return ParamertersWithRandom parameter
	 */
	public KeyParameter createParametersKey() {
		byte[] aes_key_bytes = new byte[_keySize / 8];
		secureRandom.nextBytes(aes_key_bytes);
		return new KeyParameter(aes_key_bytes);
	}

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
	public void addKeyToKeyStore(KeyStore ks, SecretKey key, String alias,
			String keyPassword) throws CryptoUtilsException {
		KeyStore.SecretKeyEntry entry = new KeyStore.SecretKeyEntry(key);
		try {
			ks.setEntry(alias, entry, new KeyStore.PasswordProtection(
					keyPassword.toCharArray()));
		} catch (KeyStoreException e) {
			throw new CryptoUtilsException("[addKeyToKeyStore] : " + e,
					e);
		}
	}

	/**
	 * Saves the key to a file
	 * 
	 * @param fileFullName
	 *            File name (Including Path and extension) in which the key will
	 *            be stored
	 * @throws CryptoUtilsException
	 */
	public void saveKeyToFile(byte[] key, String fileFullName)
			throws CryptoUtilsException {
		try {
			File file = new File(fileFullName);
			if (!file.exists()) {
				file.createNewFile();
			}
			FileOutputStream fos = new FileOutputStream(file);
			fos.write(key);
			fos.flush();
			fos.close();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			throw new CryptoUtilsException("[SaveKeyToFile]: " + e,
					e);

		} catch (IOException e) {
			// TODO Auto-generated catch block
			throw new CryptoUtilsException("[SaveKeyToFile]: " + e,
					e);

		}
	}

	/**
	 * Gets the Key from the input File
	 * 
	 * @param keyFileName
	 *            Name of File in which the key is stored
	 * @return The key readed from the file
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 */
	public byte[] getKey(String keyFileName) throws CryptoUtilsException {

		File keyFile = new File(keyFileName);
		if (keyFile.exists()) {
			byte[] bytes = new byte[(int) keyFile.length()];
			try {
				new FileInputStream(keyFile).read(bytes);
				return bytes;
			} catch (FileNotFoundException e) {
				// TODO Auto-generated catch block
				throw new CryptoUtilsException("[GetKey]: " + e,
						e);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				throw new CryptoUtilsException("[GetKey]: " + e,
						e);
			}
		} else {
			throw new CryptoUtilsException(
					"Get key from file error: No such file [" + keyFileName
							+ "]");
		}

	}

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
	public byte[] getKey(KeyStore ks, String keyAlias, String keyPassword)
			throws CryptoUtilsException {
		try {

			// Get the key from KeyStore
			Key k = ks.getKey(keyAlias, keyPassword.toCharArray());
			return k.getEncoded();

		} catch (KeyStoreException ex) {
			throw new CryptoUtilsException(
					"The keyStore is not loaded\n" + ex.getMessage(),
					ex);
		} catch (UnrecoverableKeyException ex) {
			throw new CryptoUtilsException(
					"Can't recover the key, check the keyPassword\n"
							+ ex.getMessage(), ex);
		} catch (NoSuchAlgorithmException ex) {
			throw new CryptoUtilsException(
					"Error loading the KeyStore File: the algorithm used to check the integrity of the keystore cannot be found\n"
							+ ex.getMessage(), ex);
		}
	}

	/**
	 * Creates an instance of a BlockCipher depending on the operationMode
	 * 
	 * @param operationMode
	 *            Desired operation mode
	 * @return Instance of the blockCipher that uses that operationMode
	 * @throws CryptoUtilsException
	 *             If selected operation Mode is not supported
	 */
	private BlockCipher selectOperationMode(String operationMode)
			throws CryptoUtilsException {
		BlockCipher cipher;
		// Check selected operationMode
		if (operationMode.equalsIgnoreCase(OPERATION_MODE_CBC)) {
			cipher = new CBCBlockCipher(new AESEngine());
			return cipher;
		}
		if (operationMode.equalsIgnoreCase(OPERATION_MODE_CFB)) {
			cipher = new CFBBlockCipher(new AESEngine(), 128);
			return cipher;
		}
		if (operationMode.equalsIgnoreCase(OPERATION_MODE_OFB)) {
			cipher = new OFBBlockCipher(new AESEngine(), 128);
			return cipher;
		}
		if (operationMode.equalsIgnoreCase(OPERATION_MODE_OPENPGP)) {
			cipher = new OpenPGPCFBBlockCipher(new AESEngine());
			return cipher;
		}
		if (operationMode.equalsIgnoreCase(OPERATION_MODE_PGP)) {
			cipher = new PGPCFBBlockCipher(new AESEngine(), false);
			return cipher;
		}
		throw new CryptoUtilsException("Operation Mode ["
				+ operationMode + "] is not supported");
	}

	/**
	 * Selects the padding style in base of a string
	 * 
	 * @param padding
	 *            Desired padding style name
	 * @return BlockCipherPadding instance corresponding with the desired
	 *         padding
	 * @throws CryptoUtilsException
	 *             If selected padding is not supported
	 */
	private BlockCipherPadding selectPaddingStyle(String padding)
			throws CryptoUtilsException {
		BlockCipherPadding paddingStyle;
		// Check padding style
		if (padding.equalsIgnoreCase(PADDING_TYPE_ISO10126d2)) {
			paddingStyle = new ISO10126d2Padding();
			paddingStyle.init(secureRandom);
			return paddingStyle;
		}
		if (padding.equalsIgnoreCase(PADDING_TYPE_ISO7816d4)) {
			paddingStyle = new ISO7816d4Padding();
			paddingStyle.init(secureRandom);
			return paddingStyle;
		}
		if (padding.equalsIgnoreCase(PADDING_TYPE_PKCS7)) {
			paddingStyle = new PKCS7Padding();
			paddingStyle.init(secureRandom);
			return paddingStyle;
		}
		if (padding.equalsIgnoreCase(PADDING_TYPE_X932)) {
			paddingStyle = new X923Padding();
			paddingStyle.init(secureRandom);
			return paddingStyle;
		}
		if (padding.equalsIgnoreCase(PADDING_TYPE_ZEROBYTE)) {
			paddingStyle = new ZeroBytePadding();
			paddingStyle.init(secureRandom);
			return paddingStyle;
		}
		if (padding.equalsIgnoreCase(PADDING_TYPE_NO_PADDING)) {
			return null;
		}
		throw new CryptoUtilsException("Padding [" + padding
				+ "] is not supported");

	}

	/**
	 * Encrypts a Text using the specified key with AES-[KeySize]
	 * 
	 * @param input
	 *            Plain Text to cipher
	 * @param key
	 *            Key to use
	 * @param iv
	 *            Initialization vector (16-byte array)
	 * @param operationMode
	 *            Operation Mode to be used, check out supported operationModes
	 * @param padding
	 *            Padding style to be used, check out supported paddings
	 * @return byte array containing the encrypted text
	 * @throws CryptoUtilsException
	 */
	public byte[] encrypt(byte[] input, byte[] key, byte[] iv,
			String operationMode, String padding)
			throws CryptoUtilsException {

		if (iv == null) {
			iv = new byte[16];
		}

		return aes(input, key, Boolean.TRUE, iv,
				selectOperationMode(operationMode), selectPaddingStyle(padding));
	}

	/**
	 * Encrypts a Text using the specified key with AES-[KeySize], uses PKCS7 as
	 * default padding
	 * 
	 * @param input
	 *            Plain Text to cipher
	 * @param key
	 *            Key to use
	 * @param iv
	 *            Initialization vector (16-byte array)
	 * @param operationMode
	 *            Operation Mode to be used, check out supported operationModes
	 * @return byte array containing the encrypted text
	 * @throws CryptoUtilsException
	 */
	public byte[] encrypt(byte[] input, byte[] key, byte[] iv,
			String operationMode) throws CryptoUtilsException {

		if (iv == null) {
			iv = new byte[16];
		}

		return aes(input, key, Boolean.TRUE, iv,
				selectOperationMode(operationMode),
				selectPaddingStyle(PADDING_TYPE_PKCS7));
	}

	/**
	 * Encrypts a Text using the specified key with AES-[KeySize], uses PKCS7 as
	 * default padding and CBC as default operation mode
	 * 
	 * @param input
	 *            Plain Text to cipher
	 * @param key
	 *            Key to use
	 * @param iv
	 *            Initialization vector (16-byte array)
	 * @return byte array containing the encrypted text
	 * @throws CryptoUtilsException
	 */
	public byte[] encrypt(byte[] input, byte[] key, byte[] iv)
			throws CryptoUtilsException {

		if (iv == null) {
			iv = new byte[16];
		}

		return aes(input, key, Boolean.TRUE, iv,
				selectOperationMode(OPERATION_MODE_CBC),
				selectPaddingStyle(PADDING_TYPE_PKCS7));
	}

	/**
	 * Encrypts a Text using the specified key with AES-[KeySize], uses PKCS7 as
	 * default padding and CBC as default operation mode
	 * 
	 * @param input
	 *            Plain Text to cipher
	 * @param key
	 *            Key to use
	 * @return byte array containing the encrypted text
	 * @throws CryptoUtilsException
	 */
	public byte[] encrypt(byte[] input, byte[] key)
			throws CryptoUtilsException {

		return aes(input, key, Boolean.TRUE, new byte[16],
				selectOperationMode(OPERATION_MODE_CBC),
				selectPaddingStyle(PADDING_TYPE_PKCS7));
	}

	/**
	 * Decrypts a Text using the specified key with AES-[KeySize]
	 * 
	 * @param input
	 *            Plain Text to cipher
	 * @param key
	 *            Key to use
	 * @param iv
	 *            Initialization vector (16-byte array)
	 * @param operationMode
	 *            Operation Mode to be used, check out supported operationModes
	 * @param padding
	 *            Padding style to be used, check out supported paddings
	 * @return byte array containing the encrypted text
	 * @throws CryptoUtilsException
	 */
	public byte[] decrypt(byte[] input, byte[] key, byte[] iv,
			String operationMode, String padding)
			throws CryptoUtilsException {

		if (iv == null) {
			iv = new byte[16];
		}

		return aes(input, key, Boolean.FALSE, iv,
				selectOperationMode(operationMode), selectPaddingStyle(padding));
	}

	/**
	 * Decrypts a Text using the specified key with AES-[KeySize], uses PKCS7 as
	 * default padding
	 * 
	 * @param input
	 *            Plain Text to cipher
	 * @param key
	 *            Key to use
	 * @param iv
	 *            Initialization vector (16-byte array)
	 * @param operationMode
	 *            Operation Mode to be used, check out supported operationModes
	 * @return byte array containing the encrypted text
	 * @throws CryptoUtilsException
	 */
	public byte[] decrypt(byte[] input, byte[] key, byte[] iv,
			String operationMode) throws CryptoUtilsException {

		if (iv == null) {
			iv = new byte[16];
		}

		return aes(input, key, Boolean.FALSE, iv,
				selectOperationMode(operationMode),
				selectPaddingStyle(PADDING_TYPE_PKCS7));
	}

	/**
	 * Decrypts a Text using the specified key with AES-[KeySize], uses PKCS7 as
	 * default padding and CBC as default operation mode
	 * 
	 * @param input
	 *            Plain Text to cipher
	 * @param key
	 *            Key to use
	 * @param iv
	 *            Initialization vector (16-byte array)
	 * @return byte array containing the encrypted text
	 * @throws CryptoUtilsException
	 */
	public byte[] decrypt(byte[] input, byte[] key, byte[] iv)
			throws CryptoUtilsException {

		if (iv == null) {
			iv = new byte[16];
		}

		return aes(input, key, Boolean.FALSE, iv,
				selectOperationMode(OPERATION_MODE_CBC),
				selectPaddingStyle(PADDING_TYPE_PKCS7));
	}

	/**
	 * Decrypts a Text using the specified key with AES-[KeySize], uses PKCS7 as
	 * default padding and CBC as default operation mode
	 * 
	 * @param input
	 *            Plain Text to cipher
	 * @param key
	 *            Key to use
	 * @return byte array containing the encrypted text
	 * @throws CryptoUtilsException
	 */
	public byte[] decrypt(byte[] input, byte[] key)
			throws CryptoUtilsException {

		return aes(input, key, Boolean.FALSE, new byte[16],
				selectOperationMode(OPERATION_MODE_CBC),
				selectPaddingStyle(PADDING_TYPE_PKCS7));
	}

	/**
	 * Encrypts or Decrypts the text using AES
	 * 
	 * @param input
	 *            input text for encrypt or decrypt
	 * @param key
	 *            Key to be used
	 * @param encryptionMode
	 *            true = Encrypt, False=Decrypt
	 * @param iv
	 *            Initialization vector, null if not needed
	 * @param cipher
	 *            BlockCipher instance, depends on the mode selected
	 * @param pad
	 *            Selected Padding for the process
	 * @return A byte array representing the output of the process
	 * @throws CryptoUtilsException
	 *             if something goes wrong
	 */
	private byte[] aes(byte[] input, byte[] key, Boolean encryptionMode,
			byte[] iv, BlockCipher cipher, BlockCipherPadding pad)
			throws CryptoUtilsException {

		// Creates a block cipher using the selected padding method
		BufferedBlockCipher b;
		if (pad != null) {
			b = new PaddedBufferedBlockCipher(cipher, pad);
		} else {
			b = new BufferedBlockCipher(cipher);
		}

		KeyParameter kp = new KeyParameter(key);
		if(cipher instanceof OpenPGPCFBBlockCipher){
			b.init(encryptionMode, kp);
		}else{
			b.init(encryptionMode, new ParametersWithIV(kp, iv));
		}

		byte[] out;
		if(cipher instanceof PGPCFBBlockCipher){
			int total = input.length;
			int leftOver = total % cipher.getBlockSize() - (cipher.getBlockSize() + 2);
			out = new byte[total-leftOver];
		}else{
			out = new byte[b.getOutputSize(input.length)];
		}

		int len = b.processBytes(input, 0, input.length, out, 0);

		try {
			len += b.doFinal(out, len);

			if (!encryptionMode && pad!=null) {
				
				pad = new ZeroBytePadding();
				pad.init(new SecureRandom());
				int padSize = pad.padCount(out);
				
				byte[] removedPaddingOutput = new byte[out.length - padSize];
				System.arraycopy(out,0,removedPaddingOutput,0,out.length - padSize);
				out = removedPaddingOutput;
			}

			return out;
		} catch (CryptoException e) {
			throw new CryptoUtilsException(e + " ", e);
		} catch (DataLengthException e) {
			throw new CryptoUtilsException(e + " ", e);
		} catch (IllegalStateException e) {
			throw new CryptoUtilsException(e + " ", e);
		}
	}
}
