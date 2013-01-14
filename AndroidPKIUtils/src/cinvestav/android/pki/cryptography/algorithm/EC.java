/**
 *  Created on  : 08/06/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	This class implements the common functions for EC like encrypt (ECIES),
 * 		decrypt (ECIES), keyGen, sign (ECDSA), verify (ECDSA) using the SouncyCastle
 * 		API (http://rtyley.github.com/spongycastle/)
 */
package cinvestav.android.pki.cryptography.algorithm;

import java.math.BigInteger;
import java.security.Security;

import org.spongycastle.crypto.AsymmetricCipherKeyPair;
import org.spongycastle.crypto.BufferedBlockCipher;
import org.spongycastle.crypto.Digest;
import org.spongycastle.crypto.InvalidCipherTextException;
import org.spongycastle.crypto.agreement.ECDHBasicAgreement;
import org.spongycastle.crypto.digests.SHA1Digest;
import org.spongycastle.crypto.engines.AESEngine;
import org.spongycastle.crypto.engines.IESEngine;
import org.spongycastle.crypto.generators.ECKeyPairGenerator;
import org.spongycastle.crypto.generators.KDF2BytesGenerator;
import org.spongycastle.crypto.macs.HMac;
import org.spongycastle.crypto.modes.CFBBlockCipher;
import org.spongycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.spongycastle.crypto.params.ECKeyGenerationParameters;
import org.spongycastle.crypto.params.IESParameters;
import org.spongycastle.crypto.params.IESWithCipherParameters;
import org.spongycastle.crypto.params.ParametersWithRandom;
import org.spongycastle.crypto.signers.ECDSASigner;
import org.spongycastle.jce.provider.BouncyCastleProvider;

import cinvestav.android.pki.cryptography.ec.ECDomainParameters;
import cinvestav.android.pki.cryptography.exception.CryptoUtilsException;
import cinvestav.android.pki.cryptography.key.ECKeyPair;
import cinvestav.android.pki.cryptography.key.ECPrivateKey;
import cinvestav.android.pki.cryptography.key.ECPublicKey;
import cinvestav.android.pki.cryptography.utils.CryptoUtils;

/**
 * This class implements the common functions for EC like encrypt (ECIES),
 * decrypt (ECIES), keyGen, sign (ECDSA), verify (ECDSA) using the SouncyCastle
 * API (http://rtyley.github.com/spongycastle/)
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 08/06/2012
 * @version 1.0
 */
public class EC {
	
	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	private ECDSASigner ecdsa;

	/*
	 * public static final String DIGEST_FUNCTION_SHA_1 = "SHA-1"; public
	 * static final String DIGEST_FUNCTION_SHA_224 = "SHA-224"; public
	 * static final String DIGEST_FUNCTION_SHA_256 = "SHA-256"; public
	 * static final String DIGEST_FUNCTION_SHA_384 = "SHA-384"; public
	 * static final String DIGEST_FUNCTION_SHA_512 = "SHA-512";
	 */

	/**
	 * Default constructor default
	 */
	public EC() {
		super();
		ecdsa = new ECDSASigner();
	}

	/**
	 * Generate ECKey pair in base of parameters like curve, field, order, etc
	 * 
	 * @param parameters
	 *            Parameters for the curve and the points
	 * @return A new EC Key Pair object
	 * @throws CryptoUtilsException
	 */
	public ECKeyPair generateKeys(ECDomainParameters parameters)
			throws CryptoUtilsException {
		AsymmetricCipherKeyPair tempPair;

		// Generate the EC Key Pair using the EC parameters
		ECKeyPairGenerator keyGen = new ECKeyPairGenerator();

		keyGen.init(new ECKeyGenerationParameters(parameters
				.parseToECDomainParameters(), CryptoUtils.secureRandom));

		tempPair = keyGen.generateKeyPair();

		return ECKeyPair.parse(tempPair);

	}

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
	 *            is the standard function for DSA)
	 * @return Two bigInteger array representing r and s respectively
	 * @throws CryptoUtilsException
	 *             if the digestFunction is not supported
	 */
	public BigInteger[] sign(byte[] message, ECPrivateKey privateKey,
			String digestName) throws CryptoUtilsException {
		// Gets the digest of the message
		Digest digest = CryptoUtils.selectDigest(digestName);
		digest.update(message, 0, message.length);
		byte[] digestMessage = new byte[digest.getDigestSize()];
		digest.doFinal(digestMessage, 0);

		return this.sign(digestMessage, privateKey);

	}

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
	 *            is the standard function for DSA)
	 * @return TRUE if the signature is correct, FALSE otherwise
	 * @throws CryptoUtilsException
	 *             if the signature is a valid ECDSA signature
	 */
	public Boolean verify(byte[] message, BigInteger[] sig,
			ECPublicKey publicKey, String digestName)
			throws CryptoUtilsException {
		// Gets the digest of the message
		Digest digest = CryptoUtils.selectDigest(digestName);
		digest.update(message, 0, message.length);
		byte[] digestMessage = new byte[digest.getDigestSize()];
		digest.doFinal(digestMessage, 0);

		return this.verify(digestMessage, sig, publicKey);

	}

	/**
	 * 
	 * Encrypts the input array using ECIES, this scheme offers beside
	 * encryption also authentication. Its important to mention that in this
	 * function AES-CBC will be used as BlockCipher scheme
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
	 * @return byte array representing the encrypted message
	 * @throws CryptoUtilsException
	 */
	public byte[] encrypt(byte[] input, ECPublicKey receiverPartPublicKey,
			ECPrivateKey ownPrivateKey, byte[] derivation, byte[] encoding,
			int macSize, int keySize) throws CryptoUtilsException {

		try {
			return ies(Boolean.TRUE, input, ownPrivateKey,
					receiverPartPublicKey, derivation, encoding, macSize,
					keySize);
		} catch (InvalidCipherTextException e) {
			// TODO Auto-generated catch block
			throw new CryptoUtilsException("EC Encryption error: " + e,
					e);
		}
	}

	/**
	 * 
	 * Encrypts the input array using ECIES, this scheme offers beside
	 * encryption also authentication, using simple and default KDF parameters.
	 * Its important to mention that in this function AES-CBC will be used as
	 * BlockCipher scheme
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
	 * @return byte array representing the encrypted message
	 * @throws CryptoUtilsException
	 */
	public byte[] encrypt(byte[] input, ECPublicKey receiverPartPublicKey,
			ECPrivateKey ownPrivateKey, int macSize, int keySize)
			throws CryptoUtilsException {

		try {
			byte[] d = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
			byte[] e = new byte[] { 8, 7, 6, 5, 4, 3, 2, 1 };
			return ies(Boolean.TRUE, input, ownPrivateKey,
					receiverPartPublicKey, d, e, macSize, keySize);
		} catch (InvalidCipherTextException e) {
			// TODO Auto-generated catch block
			throw new CryptoUtilsException("EC Encryption error: " + e,
					e);
		}
	}

	/**
	 * 
	 * Encrypts the input array using ECIES, this scheme offers beside
	 * encryption also authentication, using simple and default KDF parameters
	 * and a 64bit MAC key. Its important to mention that in this function
	 * AES-CBC will be used as BlockCipher scheme
	 * 
	 * @param input
	 *            Data to be encrypted
	 * @param receiverPartPublicKey
	 *            The EC public key of receiver,
	 * @param ownPrivateKey
	 *            EC Private key of the sender, for authentication proposes
	 * @param keySize
	 *            Key Size for the cipher used by IES
	 * @return byte array representing the encrypted message
	 * @throws CryptoUtilsException
	 */
	public byte[] encrypt(byte[] input, ECPublicKey receiverPartPublicKey,
			ECPrivateKey ownPrivateKey, int keySize)
			throws CryptoUtilsException {

		try {
			byte[] d = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
			byte[] e = new byte[] { 8, 7, 6, 5, 4, 3, 2, 1 };
			return ies(Boolean.TRUE, input, ownPrivateKey,
					receiverPartPublicKey, d, e, 64, keySize);
		} catch (InvalidCipherTextException e) {
			// TODO Auto-generated catch block
			throw new CryptoUtilsException("EC Encryption error: " + e,
					e);
		}
	}

	/**
	 * 
	 * Encrypts the input array using ECIES, this scheme offers beside
	 * encryption also authentication, using simple and default KDF parameters ,
	 * a 64bit MAC key and finally a 128 bit cipher key. Its important to
	 * mention that in this function AES-CBC will be used as BlockCipher scheme
	 * 
	 * @param input
	 *            Data to be encrypted
	 * @param receiverPartPublicKey
	 *            The EC public key of receiver,
	 * @param ownPrivateKey
	 *            EC Private key of the sender, for authentication proposes
	 * @param keySize
	 *            Key Size for the cipher used by IES
	 * @return byte array representing the encrypted message
	 * @throws CryptoUtilsException
	 */
	public byte[] encrypt(byte[] input, ECPublicKey receiverPartPublicKey,
			ECPrivateKey ownPrivateKey) throws CryptoUtilsException {

		try {
			byte[] d = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
			byte[] e = new byte[] { 8, 7, 6, 5, 4, 3, 2, 1 };
			return ies(Boolean.TRUE, input, ownPrivateKey,
					receiverPartPublicKey, d, e, 64, 128);
		} catch (InvalidCipherTextException e) {
			// TODO Auto-generated catch block
			throw new CryptoUtilsException("EC Encryption error: " + e,
					e);
		}
	}

	/**
	 * 
	 * Decrypts the input array using ECIES, this scheme offers beside
	 * encryption also authentication. Its important to mention that in this
	 * function AES-CBC will be used as BlockCipher scheme
	 * 
	 * @param input
	 *            Data to be decrypted
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
	 * @return byte array representing the encrypted message
	 * @throws CryptoUtilsException
	 */
	public byte[] decrypt(byte[] input, ECPublicKey senderPartPublicKey,
			ECPrivateKey ownPrivateKey, byte[] derivation, byte[] encoding,
			int macSize, int keySize) throws CryptoUtilsException {

		try {
			return ies(Boolean.FALSE, input, ownPrivateKey,
					senderPartPublicKey, derivation, encoding, macSize, keySize);
		} catch (InvalidCipherTextException e) {
			// TODO Auto-generated catch block
			throw new CryptoUtilsException("EC Decryption error: " + e,
					e);
		}
	}

	/**
	 * 
	 * Decrypts the input array using ECIES, this scheme offers beside
	 * encryption also authentication, using simple and default KDF parameters.
	 * Its important to mention that in this function AES-CBC will be used as
	 * BlockCipher scheme
	 * 
	 * @param input
	 *            Data to be decrypted
	 * @param senderPartPublicKey
	 *            The EC public key of sender,
	 * @param ownPrivateKey
	 *            Our EC Private Key, for authentication proposes
	 * @param macSize
	 *            Size of the MAC key used by the IES Scheme
	 * @param keySize
	 *            Key Size for the cipher used by IES
	 * @return byte array representing the encrypted message
	 * @throws CryptoUtilsException
	 */
	public byte[] decrypt(byte[] input, ECPublicKey senderPartPublicKey,
			ECPrivateKey ownPrivateKey, int macSize, int keySize)
			throws CryptoUtilsException {

		try {
			byte[] d = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
			byte[] e = new byte[] { 8, 7, 6, 5, 4, 3, 2, 1 };
			return ies(Boolean.FALSE, input, ownPrivateKey,
					senderPartPublicKey, d, e, macSize, keySize);
		} catch (InvalidCipherTextException e) {
			// TODO Auto-generated catch block
			throw new CryptoUtilsException("EC Decryption error: " + e,
					e);
		}
	}

	/**
	 * 
	 * Decrypts the input array using ECIES, this scheme offers beside
	 * encryption also authentication.,using simple and default KDF parameters ,
	 * and 64bit MAC key. Its important to mention that in this function AES-CBC
	 * will be used as BlockCipher scheme
	 * 
	 * @param input
	 *            Data to be decrypted
	 * @param senderPartPublicKey
	 *            The EC public key of sender,
	 * @param ownPrivateKey
	 *            Our EC Private Key, for authentication proposes
	 * @param keySize
	 *            Key Size for the cipher used by IES
	 * @return byte array representing the encrypted message
	 * @throws CryptoUtilsException
	 */
	public byte[] decrypt(byte[] input, ECPublicKey senderPartPublicKey,
			ECPrivateKey ownPrivateKey, int keySize)
			throws CryptoUtilsException {

		try {
			byte[] d = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
			byte[] e = new byte[] { 8, 7, 6, 5, 4, 3, 2, 1 };
			return ies(Boolean.FALSE, input, ownPrivateKey,
					senderPartPublicKey, d, e, 64, keySize);
		} catch (InvalidCipherTextException e) {
			// TODO Auto-generated catch block
			throw new CryptoUtilsException("EC Decryption error: " + e,
					e);
		}
	}

	/**
	 * 
	 * Decrypts the input array using ECIES, this scheme offers beside
	 * encryption also authentication, using simple and default KDF parameters ,
	 * a 64bit MAC key and finally a 128 bit cipher key. Its important to
	 * mention that in this function AES-CBC will be used as BlockCipher scheme
	 * 
	 * @param input
	 *            Data to be decrypted
	 * @param senderPartPublicKey
	 *            The EC public key of sender,
	 * @param ownPrivateKey
	 *            Our EC Private Key, for authentication proposes
	 * @return byte array representing the encrypted message
	 * @throws CryptoUtilsException
	 */
	public byte[] decrypt(byte[] input, ECPublicKey senderPartPublicKey,
			ECPrivateKey ownPrivateKey) throws CryptoUtilsException {

		try {
			byte[] d = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
			byte[] e = new byte[] { 8, 7, 6, 5, 4, 3, 2, 1 };
			return ies(Boolean.FALSE, input, ownPrivateKey,
					senderPartPublicKey, d, e, 64, 128);
		} catch (InvalidCipherTextException e) {
			// TODO Auto-generated catch block
			throw new CryptoUtilsException("EC Decryption error: " + e,
					e);
		}
	}

	/**
	 * Performs encryption/decryption of a message using ECIES
	 * 
	 * @param forEncryption
	 *            If TRUE the message will be encrypted, FALSE for decryption
	 * @param message
	 *            Message to be processed
	 * @param ownPrivateKey
	 *            for encryption, should be the senders keyPair, and for
	 *            decryption the receivers one
	 * @param counterPartPublicKey
	 *            The counterpart publicKey
	 * @param derivation
	 *            Derivation parameter for KDF
	 * @param encoding
	 *            Encoding parameter for KDF
	 * @param macSize
	 *            Size of the MAC key (in bits)
	 * @param keySize
	 *            Size of the session key (in bits)
	 * @return byte array containing the encrypted/decrypted message
	 * @throws InvalidCipherTextException
	 */
	private byte[] ies(Boolean forEncryption, byte[] input,
			ECPrivateKey ownPrivateKey, ECPublicKey counterPartPublicKey,
			byte[] derivation, byte[] encoding, int macSize, int keySize)
			throws InvalidCipherTextException {
		//
		// AES with CBC
		//
		BufferedBlockCipher c1 = new PaddedBufferedBlockCipher(
				new CFBBlockCipher(new AESEngine(), 128));

		// Declare IESEngine using ECDH Agreement for creation of the session
		// key and KDF for derivation of this key
		IESEngine i1 = new IESEngine(new ECDHBasicAgreement(),
				new KDF2BytesGenerator(new SHA1Digest()), new HMac(
						new SHA1Digest()), c1);

		// Init params for the KDF algorithm
		IESParameters p = new IESWithCipherParameters(derivation, encoding,
				macSize, keySize);

		i1.init(forEncryption, ownPrivateKey.parseToECPrivateKeyParameters(),
				counterPartPublicKey.parseToECPublicKeyParameters(), p);

		return i1.processBlock(input, 0, input.length);

	}

	/**
	 * Sign a byte array that represents the message to be signed
	 * 
	 * @param message
	 *            Message to be signed, the message should be a SHA-1 hashed
	 *            message
	 * @param privateKey
	 *            Key to be used for signing
	 * @return Two bigInteger array representing r and s respectively
	 */
	private BigInteger[] sign(byte[] message, ECPrivateKey privateKey) {

		// Create the parameters for the ECDSA algorithm, with the privateKey
		// that will be used for sign the message
		ParametersWithRandom param = new ParametersWithRandom(
				privateKey.parseToECPrivateKeyParameters(),
				CryptoUtils.secureRandom);

		// Init the signer with the parameters
		ecdsa.init(true, param);

		// Sign the message, the result will be r and s respectively
		BigInteger[] sig = ecdsa.generateSignature(message);

		return sig;
	}

	/**
	 * Verify the signature of a message
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
	private Boolean verify(byte[] message, BigInteger[] sig,
			ECPublicKey publicKey) throws CryptoUtilsException {

		// Check if the sign contains exactly two BigIntegers
		if (sig.length != 2)
			throw new CryptoUtilsException(
					"EC signature verify error: Invalid signature format");

		// Init the signer algorithm with the public key
		ecdsa.init(false, publicKey.parseToECPublicKeyParameters());

		// Verify the signature and return the result
		return ecdsa.verifySignature(message, sig[0], sig[1]);
	}
}
