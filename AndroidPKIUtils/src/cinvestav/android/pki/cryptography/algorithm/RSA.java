/**
 *  Created on  : 15/04/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	This  class implements the common functions for RSA like encrypt, decrypt, keyGen, sign, verify
 *     	using the SouncyCastle API (http://rtyley.github.com/spongycastle/)
 */
package cinvestav.android.pki.cryptography.algorithm;

import java.math.BigInteger;
import java.security.Security;

import org.spongycastle.crypto.AsymmetricBlockCipher;
import org.spongycastle.crypto.CryptoException;
import org.spongycastle.crypto.DataLengthException;
import org.spongycastle.crypto.Digest;
import org.spongycastle.crypto.encodings.ISO9796d1Encoding;
import org.spongycastle.crypto.encodings.OAEPEncoding;
import org.spongycastle.crypto.encodings.PKCS1Encoding;
import org.spongycastle.crypto.engines.RSAEngine;
import org.spongycastle.crypto.generators.RSAKeyPairGenerator;
import org.spongycastle.crypto.params.RSAKeyGenerationParameters;
import org.spongycastle.crypto.params.RSAKeyParameters;
import org.spongycastle.crypto.signers.RSADigestSigner;
import org.spongycastle.jce.provider.BouncyCastleProvider;

import cinvestav.android.pki.cryptography.exception.CryptoUtilsException;
import cinvestav.android.pki.cryptography.key.RSAKeyPair;
import cinvestav.android.pki.cryptography.key.RSAPrivateKey;
import cinvestav.android.pki.cryptography.key.RSAPublicKey;
import cinvestav.android.pki.cryptography.utils.CryptoUtils;

/**
 * @author Ing. Javier Silva Pérez - [javier]
 * 
 */
public class RSA {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	public static final String OPERATION_MODE_PKCS1 = "PKCS1";
	public static final String OPERATION_MODE_ISO9796d1 = "ISO9796d1";
	public static final String OPERATION_MODE_OAEP = "OAEP";

	/**
	 * Default constructor default
	 */
	public RSA() {
		super();
	}

	/**
	 * Generate the key pairs for RSA depending on the keySize specified (in
	 * bits)
	 * 
	 * @param keySizeInBits
	 *            Key Size must be in bits
	 * @return
	 * @throws CryptoUtilsException
	 */
	public RSAKeyPair generateKeys(int keySizeInBits)
			throws CryptoUtilsException {
		RSAKeyPairGenerator r = new RSAKeyPairGenerator();
		BigInteger publicExponent = new BigInteger("65537", 10);// publicExponent
		RSAKeyGenerationParameters params = new RSAKeyGenerationParameters(
				publicExponent, CryptoUtils.secureRandom, keySizeInBits, 70);
		r.init(params);
		return RSAKeyPair.parse(r.generateKeyPair());
	}

	/**
	 * Creates an instance of a AsymmetricBlockCipher depending on the
	 * operationMode
	 * 
	 * @param operationMode
	 *            Desired operation mode
	 * @return Instance of the blockCipher that uses that operationMode
	 * @throws CryptoUtilsException
	 *             If selected operation Mode is not supported
	 */
	private AsymmetricBlockCipher selectOperationMode(String operationMode)
			throws CryptoUtilsException {
		AsymmetricBlockCipher cipher;
		// Check selected operationMode
		if (operationMode.equalsIgnoreCase(OPERATION_MODE_PKCS1)) {
			cipher = new PKCS1Encoding(new RSAEngine());
			return cipher;
		}
		if (operationMode.equalsIgnoreCase(OPERATION_MODE_OAEP)) {
			cipher = new OAEPEncoding(new RSAEngine());
			return cipher;
		}
		if (operationMode.equalsIgnoreCase(OPERATION_MODE_ISO9796d1)) {
			cipher = new ISO9796d1Encoding(new RSAEngine());
			return cipher;
		}
		throw new CryptoUtilsException("Operation Mode [" + operationMode
				+ "] is not supported");
	}

	/**
	 * Signs the digest of the input data using RSA and the selected digest
	 * 
	 * @param input
	 *            Input message to be signed
	 * @param privateKey
	 *            Key to be used to sign the message
	 * @param digestName
	 *            Name of the digest function to use, see supported functions in
	 *            AndroidCryptoUtils as public static attributes of this class
	 * @return A byte array containing the sing of digest of the input message
	 * @throws CryptoUtilsException
	 */
	public byte[] sign(byte[] input, RSAPrivateKey privateKey, String digestName)
			throws CryptoUtilsException {
		return rsaDigestSign(privateKey.parseToRSAPrivateCrtKeyParameters(),
				input, CryptoUtils.selectDigest(digestName));
	}

	/**
	 * Signs the digest of the input data using RSA and SHA-1 as default digest
	 * function
	 * 
	 * @param input
	 *            Input message to be signed
	 * @param privateKey
	 *            Key to be used to sign the message
	 * @return A byte array containing the sing of digest of the input message
	 * @throws CryptoUtilsException
	 */
	public byte[] sign(byte[] input, RSAPrivateKey privateKey)
			throws CryptoUtilsException {
		return rsaDigestSign(privateKey.parseToRSAPrivateCrtKeyParameters(),
				input,
				CryptoUtils.selectDigest(CryptoUtils.DIGEST_FUNCTION_SHA_1));
	}

	/**
	 * Verify a message signature using the public key and the original message
	 * 
	 * @param input
	 *            Original message
	 * @param sign
	 *            Sign of the message
	 * @param publicKey
	 *            Key that will be used to verify sign
	 * @param digestName
	 *            Digest Function Name used for sign the message
	 * @return TRUE if the sign is OK, FALSE otherwise
	 * @throws CryptoUtilsException
	 */
	public Boolean verify(byte[] input, byte[] sign, RSAPublicKey publicKey,
			String digestName) throws CryptoUtilsException {
		return rsaDigestSignVerify(publicKey.parseToRSAKeyParameters(), input,
				CryptoUtils.selectDigest(digestName), sign);
	}

	/**
	 * Verify a message signature using the public key and the original message
	 * using SHA-1 as default digest function
	 * 
	 * @param input
	 *            Original message
	 * @param sign
	 *            Sign of the message
	 * @param publicKey
	 *            Key that will be used to verify sign
	 * @return TRUE if the sign is OK, FALSE otherwise
	 * @throws CryptoUtilsException
	 */
	public Boolean verify(byte[] input, byte[] sign, RSAPublicKey publicKey)
			throws CryptoUtilsException {
		return rsaDigestSignVerify(publicKey.parseToRSAKeyParameters(), input,
				CryptoUtils.selectDigest(CryptoUtils.DIGEST_FUNCTION_SHA_1),
				sign);
	}

	/**
	 * Encrypts the input value using RSA, the publicKey and the selected
	 * operation Mode
	 * 
	 * @param input
	 *            Data to be encrypted
	 * @param pubKeyParameters
	 *            Public key that will be used to encrypt
	 * @param operationMode
	 *            RSA Operation Mode, check supported modes
	 * @return encrypted byte array
	 * @throws CryptoUtilsException
	 */
	public byte[] encrypt(byte[] input, RSAPublicKey publicKey,
			String operationMode) throws CryptoUtilsException {

		return rsaEncrypt(true, input, selectOperationMode(operationMode),
				publicKey.parseToRSAKeyParameters());
	}

	/**
	 * Encrypts the input value using RSA, the publicKey and PKCS1 as default
	 * operation mode
	 * 
	 * @param input
	 *            Data to be encrypted
	 * @param pubKeyParameters
	 *            Public key that will be used to encrypt
	 * @param operationMode
	 *            RSA Operation Mode, check supported modes
	 * @return encrypted byte array
	 * @throws CryptoUtilsException
	 */
	public byte[] encrypt(byte[] input, RSAPublicKey publicKey)
			throws CryptoUtilsException {

		return rsaEncrypt(true, input,
				selectOperationMode(OPERATION_MODE_PKCS1),
				publicKey.parseToRSAKeyParameters());
	}

	/**
	 * Decrypts the input value using RSA, the publicKey and the selected
	 * operation Mode
	 * 
	 * @param input
	 *            Data to be decrypted
	 * @param privateKey
	 *            Private key that will be used to decrypt
	 * @param operationMode
	 *            RSA Operation Mode, check supported modes
	 * @return encrypted byte array
	 * @throws CryptoUtilsException
	 */
	public byte[] decrypt(byte[] input, RSAPrivateKey privateKey,
			String operationMode) throws CryptoUtilsException {

		return rsaEncrypt(false, input, selectOperationMode(operationMode),
				privateKey.parseToRSAPrivateCrtKeyParameters());
	}

	/**
	 * Decrypts the input value using RSA, the privateKey and PKCS1 as default
	 * operation mode
	 * 
	 * @param input
	 *            Data to be decrypted
	 * @param privateKey
	 *            Private key that will be used to encrypt
	 * @param operationMode
	 *            RSA Operation Mode, check supported modes
	 * @return decrypted byte array
	 * @throws CryptoUtilsException
	 */
	public byte[] decrypt(byte[] input, RSAPrivateKey privateKey)
			throws CryptoUtilsException {

		return rsaEncrypt(false, input,
				selectOperationMode(OPERATION_MODE_PKCS1),
				privateKey.parseToRSAPrivateCrtKeyParameters());
	}

	/**
	 * Encrypts and Decrypts input bytes using RSA
	 * 
	 * @param encryptionMode
	 *            When is set to TRUE encrypt, FALSE decrypt
	 * @param input
	 *            Input to be processed
	 * @param eng
	 *            AsymmetricBlockCipher to be used, depends on the selected
	 *            operation mode
	 * @param pubKeyParameters
	 *            Public key for encrypt and Private Key for decrypt
	 * @return Processed byte array
	 * @throws CryptoUtilsException
	 */
	private byte[] rsaEncrypt(Boolean encryptionMode, byte[] input,
			AsymmetricBlockCipher eng, RSAKeyParameters keyParameters)
			throws CryptoUtilsException {

		// byte[] data = Hex.decode(input);
		byte[] data;
		eng.init(encryptionMode, keyParameters);

		try {
			data = eng.processBlock(input, 0, input.length);
			return data;
		} catch (Exception e) {
			throw new CryptoUtilsException("RSA Encrypt: " + e, e);
		}

	}

	/**
	 * Signs the Digest of the input and return the byte array representing the
	 * resulting sign
	 * 
	 * @param keyParameters
	 *            Private key that must be used for sign the digest of the
	 *            message
	 * @param input
	 *            Complete message to be signed
	 * @param digest
	 *            Digest method to be used
	 * @return a byte array that contains the sign of digest of the input
	 * @throws CryptoUtilsException
	 *             if something goes wrong
	 */
	private byte[] rsaDigestSign(RSAKeyParameters keyParameters, byte[] input,
			Digest digest) throws CryptoUtilsException {
		RSADigestSigner signer = new RSADigestSigner(digest);
		signer.init(true, keyParameters);
		signer.update(input, 0, input.length);
		byte[] sig;
		try {
			sig = signer.generateSignature();
			return sig;
		} catch (DataLengthException e) {
			// TODO Auto-generated catch block
			throw new CryptoUtilsException("RSA Digest Sign: " + e, e);
		} catch (CryptoException e) {
			// TODO Auto-generated catch block
			throw new CryptoUtilsException("RSA Digest Sign: " + e, e);
		}
	}

	/**
	 * Verify the sign of the digest of a message
	 * 
	 * @param keyParameters
	 *            Public key to be used for verify the sign
	 * @param input
	 *            Complete message
	 * @param digest
	 *            Digest method that will be used
	 * @param sign
	 *            Sign of the digest of the input message
	 * @return TRUE if the sign verification is correct, FALSE otherwise
	 */
	private Boolean rsaDigestSignVerify(RSAKeyParameters keyParameters,
			byte[] input, Digest digest, byte[] sign) {

		RSADigestSigner signer = new RSADigestSigner(digest);
		signer.init(false, keyParameters);
		signer.update(input, 0, input.length);
		return signer.verifySignature(sign);

	}
}
