/**
 *  Created on  : 06/06/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	Run all the test for EC functions available in the PKI library
 */
package cinvestav.pki.androidpkiutilstest;

import java.io.File;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;

import org.spongycastle.util.encoders.Base64;
import org.spongycastle.util.encoders.Hex;

import android.os.Environment;
import cinvestav.android.pki.cryptography.cert.CertificateInformationKeys;
import cinvestav.android.pki.cryptography.ec.ECDomainParameters;
import cinvestav.android.pki.cryptography.exception.CryptoUtilsException;
import cinvestav.android.pki.cryptography.exception.CryptoUtilsX509ExtensionException;
import cinvestav.android.pki.cryptography.key.ECKeyPair;
import cinvestav.android.pki.cryptography.key.ECPrivateKey;
import cinvestav.android.pki.cryptography.key.ECPublicKey;
import cinvestav.android.pki.cryptography.utils.AsymmetricCryptoUtils;
import cinvestav.android.pki.cryptography.utils.CryptoUtils;
import cinvestav.android.pki.cryptography.utils.X509Utils;
import cinvestav.android.pki.cryptography.utils.X509UtilsDictionary;
import cinvestav.android.pki.utils.LogUtil;

/**
 * Run all the test for EC functions available in the PKI library
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 06/06/2012
 * @version 1.0
 */
public class ECTestRunner {
	// public static final String TAG = "SCCIPHERTEST";
	protected static LogUtil log = new LogUtil("ANDROID_PKI_UTILS");
	// private Android androidAsymmetricCryptoUtils;
	private String defaultEncoder = CryptoUtils.ENCODER_HEX;
	private AsymmetricCryptoUtils asymmetricCryptoUtils;
	private X509Utils _X509Utils;
	String logFileName = "performance_ec_d1";
	SecureRandom rand;

	public ECTestRunner() throws CryptoUtilsException {
		asymmetricCryptoUtils = new AsymmetricCryptoUtils();
		rand = new SecureRandom();
		try {
			_X509Utils = new X509Utils();
		} catch (CryptoUtilsException e) {

			e.printStackTrace();
			log.error("testX509CertificateV3 = " + e.getMessage(), e.getCause());
		}
	}

	public void runTest(Boolean detailResult) {
		log.info(" ********* EC Test Begin *********");
		String nistCurveName;
		nistCurveName = ECDomainParameters.NIST_CURVE_P_192;
		runTest(nistCurveName, detailResult);

		/*
		 * nistCurveName = ECDomainParameters.NIST_CURVE_P_224;
		 * runTest(nistCurveName, detailResult);
		 * 
		 * nistCurveName = ECDomainParameters.NIST_CURVE_P_256;
		 * runTest(nistCurveName, detailResult);
		 * 
		 * nistCurveName = ECDomainParameters.NIST_CURVE_P_384;
		 * runTest(nistCurveName, detailResult);
		 * 
		 * nistCurveName = ECDomainParameters.NIST_CURVE_P_521;
		 * runTest(nistCurveName, detailResult);
		 */

		/*
		 * nistCurveName = ECDomainParameters.NIST_CURVE_B_163;
		 * runTest(nistCurveName, detailResult);
		 */
		/*
		 * nistCurveName = ECDomainParameters.NIST_CURVE_B_233;
		 * runTest(nistCurveName, detailResult);
		 * 
		 * nistCurveName = ECDomainParameters.NIST_CURVE_B_283;
		 * runTest(nistCurveName, detailResult);
		 * 
		 * nistCurveName = ECDomainParameters.NIST_CURVE_B_409;
		 * runTest(nistCurveName, detailResult);
		 * 
		 * nistCurveName = ECDomainParameters.NIST_CURVE_B_571;
		 * runTest(nistCurveName, detailResult);
		 */

	}

	private void runTest(String nistCurveName, Boolean detailResult) {
		// testKeyGen(keySizeInBits);

		testEncodeDecodeKey(nistCurveName, detailResult);
		testSaveAndLoadKeyFile(nistCurveName, detailResult);

		SecureRandom secureRandom = new SecureRandom();
		/*
		 * for (int i = 0; i < 10; i++) { int inputSize =
		 * secureRandom.nextInt(4098); log.info("---- Input Size: " + inputSize
		 * + " ---- "); testSignVerify(nistCurveName, detailResult, inputSize);
		 * testEncryptDecrypt(nistCurveName, detailResult, inputSize);
		 * testSaveAndLoadKeyFile(nistCurveName, detailResult);
		 * testEncodeDecodeKey(nistCurveName,detailResult); }
		 */

		// Integer inputSize = 512;
		// testKeyGen(nistCurveName);
		// testSignVerify(nistCurveName, detailResult, inputSize);
		// testEncryptDecrypt(nistCurveName, detailResult, inputSize);
		// testSaveAndLoadKeyFile(nistCurveName, detailResult);

		// testEncryptDecryptRandom(keySizeInBits, detailResult, 127);
		// testEncryptDecryptRandom(keySizeInBits, detailResult, 12);
	}

	public void runTestTiming() {

		log.toFile("***************************************", logFileName);

		performKeyGenTiming(ECDomainParameters.NIST_CURVE_P_192);
		performKeyGenTiming(ECDomainParameters.NIST_CURVE_P_256);
		performKeyGenTiming(ECDomainParameters.NIST_CURVE_P_384);

		testSaveAndLoadKeyFileTiming(ECDomainParameters.NIST_CURVE_P_192);
		testSaveAndLoadKeyFileTiming(ECDomainParameters.NIST_CURVE_P_256);
		testSaveAndLoadKeyFileTiming(ECDomainParameters.NIST_CURVE_P_384);
		
		testEncryptDecryptRandomTiming(ECDomainParameters.NIST_CURVE_P_192,
				1024);
		testEncryptDecryptRandomTiming(ECDomainParameters.NIST_CURVE_P_192,
				3072);
		testEncryptDecryptRandomTiming(ECDomainParameters.NIST_CURVE_P_256,
				1024);
		testEncryptDecryptRandomTiming(ECDomainParameters.NIST_CURVE_P_256,
				3072);
		testEncryptDecryptRandomTiming(ECDomainParameters.NIST_CURVE_P_384,
				1024);
		testEncryptDecryptRandomTiming(ECDomainParameters.NIST_CURVE_P_384,
				3072);

		testSignVerifyRandomTiming(ECDomainParameters.NIST_CURVE_P_192, 1024);
		testSignVerifyRandomTiming(ECDomainParameters.NIST_CURVE_P_192, 3072);
		testSignVerifyRandomTiming(ECDomainParameters.NIST_CURVE_P_256, 1024);
		testSignVerifyRandomTiming(ECDomainParameters.NIST_CURVE_P_256, 3072);
		testSignVerifyRandomTiming(ECDomainParameters.NIST_CURVE_P_384, 1024);
		testSignVerifyRandomTiming(ECDomainParameters.NIST_CURVE_P_384, 3072);
	}

	/**
	 * Test the Key Generation Process
	 * 
	 * @param keySizeInBits
	 */
	private void testKeyGen(String nistCurveName) {
		log.info("[" + nistCurveName + "] ---- Key Generation ---- ");
		log.info("[" + nistCurveName + "] ---- NIST CURVES ---- ");
		performKeyGen(nistCurveName);
	}

	private void testEncryptDecrypt(String curveName, Boolean details,
			int inputSize) {
		log.info("---- ENCRYPT DECRYPT [" + inputSize + "]----");

		ECKeyPair receiverKey;
		ECKeyPair senderKey;
		// ECKeyPair otherKey;
		byte[] data = new byte[inputSize];
		String dataStr;

		// Generate Key and random input data
		try {
			receiverKey = asymmetricCryptoUtils.generateKeys(curveName);
			senderKey = asymmetricCryptoUtils.generateKeys(curveName);
			// otherKey =
			// androidAsymmetricCryptoUtils.generateKeys(curveName);
			SecureRandom random = new SecureRandom();
			random.nextBytes(data);

			// keyStr = new String(Base64.encode(key));
			if (defaultEncoder.equalsIgnoreCase(CryptoUtils.ENCODER_BASE64)) {
				dataStr = new String(Base64.encode(data));
			} else {
				dataStr = new String(Hex.encode(data));
			}

			if (details) {
				// log.info("KEY= " + keyStr);
				log.info("DATA= " + dataStr);
			}

			byte[] derivation = new byte[20];
			byte[] encoding = new byte[20];

			random.nextBytes(derivation);
			random.nextBytes(encoding);

			// derivation = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
			// encoding = new byte[] { 8, 7, 6, 5, 4, 3, 2, 1 };

			Integer macSize;
			Integer keySize;

			// Perform Test
			macSize = 64;
			keySize = 128;
			performEncryptDecrypt(data, receiverKey, senderKey, derivation,
					encoding, macSize, keySize, details, curveName);

			String encoder;
			encoder = CryptoUtils.ENCODER_BASE64;
			dataStr = new String(Base64.encode(data));
			// Perform Test
			performEncryptDecrypt(dataStr, receiverKey, senderKey, derivation,
					encoding, macSize, keySize, details, curveName, encoder);

			encoder = CryptoUtils.ENCODER_HEX;
			dataStr = new String(Hex.encode(data));
			// Perform Test
			performEncryptDecrypt(dataStr, receiverKey, senderKey, derivation,
					encoding, macSize, keySize, details, curveName, encoder);

			macSize = 128;
			keySize = 192;
			performEncryptDecrypt(data, receiverKey, senderKey, derivation,
					encoding, macSize, keySize, details, curveName);

			encoder = CryptoUtils.ENCODER_BASE64;
			dataStr = new String(Base64.encode(data));
			// Perform Test
			performEncryptDecrypt(dataStr, receiverKey, senderKey, derivation,
					encoding, macSize, keySize, details, curveName, encoder);

			encoder = CryptoUtils.ENCODER_HEX;
			dataStr = new String(Hex.encode(data));
			// Perform Test
			performEncryptDecrypt(dataStr, receiverKey, senderKey, derivation,
					encoding, macSize, keySize, details, curveName, encoder);

			// ----------- Change Mac and Key
			macSize = 128;
			keySize = 256;
			performEncryptDecrypt(data, receiverKey, senderKey, derivation,
					encoding, macSize, keySize, details, curveName);

			encoder = CryptoUtils.ENCODER_BASE64;
			dataStr = new String(Base64.encode(data));
			// Perform Test
			performEncryptDecrypt(dataStr, receiverKey, senderKey, derivation,
					encoding, macSize, keySize, details, curveName, encoder);

			encoder = CryptoUtils.ENCODER_HEX;
			dataStr = new String(Hex.encode(data));
			// Perform Test
			performEncryptDecrypt(dataStr, receiverKey, senderKey, derivation,
					encoding, macSize, keySize, details, curveName, encoder);

			// ----------- Change Mac and Key
			macSize = 256;
			keySize = 256;
			performEncryptDecrypt(data, receiverKey, senderKey, derivation,
					encoding, macSize, keySize, details, curveName);

			encoder = CryptoUtils.ENCODER_BASE64;
			dataStr = new String(Base64.encode(data));
			// Perform Test
			performEncryptDecrypt(dataStr, receiverKey, senderKey, derivation,
					encoding, macSize, keySize, details, curveName, encoder);

			encoder = CryptoUtils.ENCODER_HEX;
			dataStr = new String(Hex.encode(data));
			// Perform Test
			performEncryptDecrypt(dataStr, receiverKey, senderKey, derivation,
					encoding, macSize, keySize, details, curveName, encoder);
		} catch (CryptoUtilsException e) {

			e.printStackTrace();
			log.error("EC Encrypt / Decrypt Error: " + e.getMessage());
		}
	}

	/**
	 * Make the test for sign and verify with ECDSA using different parameters
	 * 
	 * @param nistCurveName
	 * @param details
	 * @param inputSize
	 */
	private void testSignVerify(String nistCurveName, Boolean details,
			int inputSize) {
		log.info("---- SIGN VERIFY [" + inputSize + "]----");

		ECKeyPair key;
		byte[] data = new byte[inputSize];
		String dataStr;

		// Generate Key and random input data
		try {
			key = asymmetricCryptoUtils.generateKeys(nistCurveName);

			SecureRandom random = new SecureRandom();
			random.nextBytes(data);

			// keyStr = new String(Base64.encode(key));
			if (defaultEncoder.equalsIgnoreCase(CryptoUtils.ENCODER_BASE64)) {
				dataStr = new String(Base64.encode(data));
			} else {
				dataStr = new String(Hex.encode(data));
			}

			if (details) {
				// log.info("KEY= " + keyStr);
				log.info("DATA= " + dataStr);
			}

			// Perform Test
			// SHA-1
			performSignVerify(data, key.getPublicKey(), key.getPrivateKey(),
					CryptoUtils.DIGEST_FUNCTION_SHA_1, details, nistCurveName,
					Boolean.FALSE);
			// SHA-224
			performSignVerify(data, key.getPublicKey(), key.getPrivateKey(),
					CryptoUtils.DIGEST_FUNCTION_SHA_224, details,
					nistCurveName, Boolean.FALSE);
			// SHA-256
			performSignVerify(data, key.getPublicKey(), key.getPrivateKey(),
					CryptoUtils.DIGEST_FUNCTION_SHA_256, details,
					nistCurveName, Boolean.FALSE);
			// SHA-384
			performSignVerify(data, key.getPublicKey(), key.getPrivateKey(),
					CryptoUtils.DIGEST_FUNCTION_SHA_384, details,
					nistCurveName, Boolean.FALSE);
			// SHA-512
			performSignVerify(data, key.getPublicKey(), key.getPrivateKey(),
					CryptoUtils.DIGEST_FUNCTION_SHA_512, details,
					nistCurveName, Boolean.FALSE);

			// MD2
			performSignVerify(data, key.getPublicKey(), key.getPrivateKey(),
					CryptoUtils.DIGEST_FUNCTION_MD2, details, nistCurveName,
					Boolean.FALSE);
			// MD4
			performSignVerify(data, key.getPublicKey(), key.getPrivateKey(),
					CryptoUtils.DIGEST_FUNCTION_MD4, details, nistCurveName,
					Boolean.FALSE);
			// MD5
			performSignVerify(data, key.getPublicKey(), key.getPrivateKey(),
					CryptoUtils.DIGEST_FUNCTION_MD5, details, nistCurveName,
					Boolean.FALSE);

			// RIPEMD128
			performSignVerify(data, key.getPublicKey(), key.getPrivateKey(),
					CryptoUtils.DIGEST_FUNCTION_RIPEMD128, details,
					nistCurveName, Boolean.FALSE);
			// RIPEMD160
			performSignVerify(data, key.getPublicKey(), key.getPrivateKey(),
					CryptoUtils.DIGEST_FUNCTION_RIPEMD160, details,
					nistCurveName, Boolean.FALSE);
			// RIPEMD256
			performSignVerify(data, key.getPublicKey(), key.getPrivateKey(),
					CryptoUtils.DIGEST_FUNCTION_RIPEMD256, details,
					nistCurveName, Boolean.FALSE);

			String encoder;
			encoder = CryptoUtils.ENCODER_HEX;
			dataStr = new String(Hex.encode(data));
			// SHA-1
			performSignVerify(dataStr, key.getPublicKey(), key.getPrivateKey(),
					CryptoUtils.DIGEST_FUNCTION_SHA_1, encoder, details,
					nistCurveName, Boolean.FALSE);
			// SHA-224
			performSignVerify(dataStr, key.getPublicKey(), key.getPrivateKey(),
					CryptoUtils.DIGEST_FUNCTION_SHA_224, encoder, details,
					nistCurveName, Boolean.FALSE);
			// SHA-256
			performSignVerify(dataStr, key.getPublicKey(), key.getPrivateKey(),
					CryptoUtils.DIGEST_FUNCTION_SHA_256, encoder, details,
					nistCurveName, Boolean.FALSE);
			// SHA-384
			performSignVerify(dataStr, key.getPublicKey(), key.getPrivateKey(),
					CryptoUtils.DIGEST_FUNCTION_SHA_384, encoder, details,
					nistCurveName, Boolean.FALSE);
			// SHA-512
			performSignVerify(dataStr, key.getPublicKey(), key.getPrivateKey(),
					CryptoUtils.DIGEST_FUNCTION_SHA_512, encoder, details,
					nistCurveName, Boolean.FALSE);

			// MD2
			performSignVerify(dataStr, key.getPublicKey(), key.getPrivateKey(),
					CryptoUtils.DIGEST_FUNCTION_MD2, encoder, details,
					nistCurveName, Boolean.FALSE);
			// MD4
			performSignVerify(dataStr, key.getPublicKey(), key.getPrivateKey(),
					CryptoUtils.DIGEST_FUNCTION_MD4, encoder, details,
					nistCurveName, Boolean.FALSE);
			// MD5
			performSignVerify(dataStr, key.getPublicKey(), key.getPrivateKey(),
					CryptoUtils.DIGEST_FUNCTION_MD5, encoder, details,
					nistCurveName, Boolean.FALSE);

			// RIPEMD128
			performSignVerify(dataStr, key.getPublicKey(), key.getPrivateKey(),
					CryptoUtils.DIGEST_FUNCTION_RIPEMD128, encoder, details,
					nistCurveName, Boolean.FALSE);
			// RIPEMD160
			performSignVerify(dataStr, key.getPublicKey(), key.getPrivateKey(),
					CryptoUtils.DIGEST_FUNCTION_RIPEMD160, encoder, details,
					nistCurveName, Boolean.FALSE);
			// RIPEMD256
			performSignVerify(dataStr, key.getPublicKey(), key.getPrivateKey(),
					CryptoUtils.DIGEST_FUNCTION_RIPEMD256, encoder, details,
					nistCurveName, Boolean.FALSE);

			encoder = CryptoUtils.ENCODER_BASE64;
			dataStr = new String(Base64.encode(data));
			// SHA-1
			performSignVerify(dataStr, key.getPublicKey(), key.getPrivateKey(),
					CryptoUtils.DIGEST_FUNCTION_SHA_1, encoder, details,
					nistCurveName, Boolean.FALSE);
			// SHA-224
			performSignVerify(dataStr, key.getPublicKey(), key.getPrivateKey(),
					CryptoUtils.DIGEST_FUNCTION_SHA_224, encoder, details,
					nistCurveName, Boolean.FALSE);
			// SHA-256
			performSignVerify(dataStr, key.getPublicKey(), key.getPrivateKey(),
					CryptoUtils.DIGEST_FUNCTION_SHA_256, encoder, details,
					nistCurveName, Boolean.FALSE);
			// SHA-384
			performSignVerify(dataStr, key.getPublicKey(), key.getPrivateKey(),
					CryptoUtils.DIGEST_FUNCTION_SHA_384, encoder, details,
					nistCurveName, Boolean.FALSE);
			// SHA-512
			performSignVerify(dataStr, key.getPublicKey(), key.getPrivateKey(),
					CryptoUtils.DIGEST_FUNCTION_SHA_512, encoder, details,
					nistCurveName, Boolean.FALSE);

			// MD2
			performSignVerify(dataStr, key.getPublicKey(), key.getPrivateKey(),
					CryptoUtils.DIGEST_FUNCTION_MD2, encoder, details,
					nistCurveName, Boolean.FALSE);
			// MD4
			performSignVerify(dataStr, key.getPublicKey(), key.getPrivateKey(),
					CryptoUtils.DIGEST_FUNCTION_MD4, encoder, details,
					nistCurveName, Boolean.FALSE);
			// MD5
			performSignVerify(dataStr, key.getPublicKey(), key.getPrivateKey(),
					CryptoUtils.DIGEST_FUNCTION_MD5, encoder, details,
					nistCurveName, Boolean.FALSE);

			// RIPEMD128
			performSignVerify(dataStr, key.getPublicKey(), key.getPrivateKey(),
					CryptoUtils.DIGEST_FUNCTION_RIPEMD128, encoder, details,
					nistCurveName, Boolean.FALSE);
			// RIPEMD160
			performSignVerify(dataStr, key.getPublicKey(), key.getPrivateKey(),
					CryptoUtils.DIGEST_FUNCTION_RIPEMD160, encoder, details,
					nistCurveName, Boolean.FALSE);
			// RIPEMD256
			performSignVerify(dataStr, key.getPublicKey(), key.getPrivateKey(),
					CryptoUtils.DIGEST_FUNCTION_RIPEMD256, encoder, details,
					nistCurveName, Boolean.FALSE);

			encoder = "OTHER";
			dataStr = new String(data);
			// SHA-1
			performSignVerify(dataStr, key.getPublicKey(), key.getPrivateKey(),
					CryptoUtils.DIGEST_FUNCTION_SHA_1, encoder, details,
					nistCurveName, Boolean.FALSE);
			// SHA-224
			performSignVerify(dataStr, key.getPublicKey(), key.getPrivateKey(),
					CryptoUtils.DIGEST_FUNCTION_SHA_224, encoder, details,
					nistCurveName, Boolean.FALSE);
			// SHA-256
			performSignVerify(dataStr, key.getPublicKey(), key.getPrivateKey(),
					CryptoUtils.DIGEST_FUNCTION_SHA_256, encoder, details,
					nistCurveName, Boolean.FALSE);
			// SHA-384
			performSignVerify(dataStr, key.getPublicKey(), key.getPrivateKey(),
					CryptoUtils.DIGEST_FUNCTION_SHA_384, encoder, details,
					nistCurveName, Boolean.FALSE);
			// SHA-512
			performSignVerify(dataStr, key.getPublicKey(), key.getPrivateKey(),
					CryptoUtils.DIGEST_FUNCTION_SHA_512, encoder, details,
					nistCurveName, Boolean.FALSE);

			// MD2
			performSignVerify(dataStr, key.getPublicKey(), key.getPrivateKey(),
					CryptoUtils.DIGEST_FUNCTION_MD2, encoder, details,
					nistCurveName, Boolean.FALSE);
			// MD4
			performSignVerify(dataStr, key.getPublicKey(), key.getPrivateKey(),
					CryptoUtils.DIGEST_FUNCTION_MD4, encoder, details,
					nistCurveName, Boolean.FALSE);
			// MD5
			performSignVerify(dataStr, key.getPublicKey(), key.getPrivateKey(),
					CryptoUtils.DIGEST_FUNCTION_MD5, encoder, details,
					nistCurveName, Boolean.FALSE);

			// RIPEMD128
			performSignVerify(dataStr, key.getPublicKey(), key.getPrivateKey(),
					CryptoUtils.DIGEST_FUNCTION_RIPEMD128, encoder, details,
					nistCurveName, Boolean.FALSE);
			// RIPEMD160
			performSignVerify(dataStr, key.getPublicKey(), key.getPrivateKey(),
					CryptoUtils.DIGEST_FUNCTION_RIPEMD160, encoder, details,
					nistCurveName, Boolean.FALSE);
			// RIPEMD256
			performSignVerify(dataStr, key.getPublicKey(), key.getPrivateKey(),
					CryptoUtils.DIGEST_FUNCTION_RIPEMD256, encoder, details,
					nistCurveName, Boolean.FALSE);

			// Change the public or private key
			ECKeyPair keyS = asymmetricCryptoUtils.generateKeys(nistCurveName);
			// SHA-1
			performSignVerify(data, keyS.getPublicKey(), key.getPrivateKey(),
					CryptoUtils.DIGEST_FUNCTION_SHA_1, details, nistCurveName,
					Boolean.TRUE);

		} catch (CryptoUtilsException e) {

			log.error("EC Sign / Verify Error: " + e.getMessage());
		}
	}

	/**
	 * Perform the EC key generation for different nist curves
	 * 
	 * @param primeSizeInBits
	 * @param nistCurveName
	 */
	private void performKeyGen(String nistCurveName) {
		log.info("---- CURVE : " + nistCurveName + "---- ");
		// Generate the EC key and display it
		ECKeyPair key;
		try {
			key = asymmetricCryptoUtils.generateKeys(nistCurveName);
			log.info("[" + nistCurveName + "] KEY = "
					+ key.toString(defaultEncoder));
		} catch (CryptoUtilsException e) {

			e.printStackTrace();
			log.error("EC Key Gen Error: " + e.getMessage());
		}
	}

	/**
	 * Perform the EC key generation for different nist curves
	 * 
	 * @param primeSizeInBits
	 * @param nistCurveName
	 */
	private void performKeyGenTiming(String nistCurveName) {

		long startnow;
		long endnow;
		long total = 0;
		int totalRounds = 150;

		for (int j = 0; j < totalRounds; j++) {
			// Generate the EC key and display it

			try {
				startnow = java.lang.System.nanoTime();
				asymmetricCryptoUtils.generateKeys(nistCurveName);
				endnow = java.lang.System.nanoTime();
				total += (endnow - startnow);

			} catch (CryptoUtilsException e) {

				e.printStackTrace();
				log.error("EC Key Gen Error: " + e.getMessage());
				log.toFile("EC Key Gen Error: " + e.getMessage(), logFileName);
			}
		}

		String totalStr = "[" + nistCurveName + "] KEYGEN= "
				+ (total / (totalRounds * 1.0));
		log.info(totalStr);
		log.toFile(totalStr, logFileName);
	}

	/**
	 * Perform the signing of a message and the verification of that signature
	 * and determine if its correct or not
	 * 
	 * @param data
	 *            Data to be signed
	 * @param publicKey
	 *            Public key to verify the sign
	 * @param privateKey
	 *            Private Key to sign the data
	 * @param digestName
	 *            name of the digest Function to use in the signature
	 * @param details
	 *            if the test should write detail result to the log
	 * @param primeSize
	 *            The key prime size that is been using in this test
	 * @param tamperParams
	 *            If FALSE, the verification should be true so the result of the
	 *            test will be OK, but when TRUE, indicates that one of the
	 *            parameters is tampered (sign, data or wrong public-private
	 *            keys) are using so the result of the verification is false,
	 *            but the result of the test is OK
	 */
	private void performSignVerify(byte[] data, ECPublicKey publicKey,
			ECPrivateKey privateKey, String digestName, Boolean details,
			String curveName, Boolean tamperParams) {
		BigInteger[] sign;
		Boolean verifyResult;

		String signStr;
		String res;

		try {
			// Sign using the specified parameters
			sign = asymmetricCryptoUtils.sign(data, privateKey, digestName);

			if (defaultEncoder.equalsIgnoreCase(CryptoUtils.ENCODER_BASE64)) {
				signStr = "r = "
						+ new String(Base64.encode(sign[0].toByteArray()))
						+ " s = "
						+ new String(Base64.encode(sign[1].toByteArray()));
			} else {
				signStr = "r = "
						+ new String(Hex.encode(sign[0].toByteArray()))
						+ " s = "
						+ new String(Hex.encode(sign[1].toByteArray()));
			}

			// Verify using the specified parameters
			verifyResult = asymmetricCryptoUtils.verify(data, sign, publicKey,
					digestName);

			res = verifyResult || tamperParams ? "OK" : "FAIL";

			log.info("[" + curveName + ": " + digestName + " - BYTE" + "] - "
					+ res);
			if (details) {
				log.info("SIGN= " + signStr);
				log.info("VERIFY RES= " + verifyResult);
			}
		} catch (CryptoUtilsException e) {

			log.error("SIGN/VERIFY Error: " + e.getMessage());
		}
	}

	/**
	 * Perform the signing of a message and the verification of that signature
	 * and determine if its correct or not
	 * 
	 * @param data
	 *            Data to be signed
	 * @param publicKey
	 *            Public key to verify the sign
	 * @param privateKey
	 *            Private Key to sign the data
	 * @param digestName
	 *            name of the digest Function to use in the signature
	 * @param encoder
	 *            Encoder for the result
	 * @param details
	 *            if the test should write detail result to the log
	 * @param primeSize
	 *            The key prime size that is been using in this test
	 * @param tamperParams
	 *            If FALSE, the verification should be true so the result of the
	 *            test will be OK, but when TRUE, indicates that one of the
	 *            parameters is tampered (sign, data or wrong public-private
	 *            keys) are using so the result of the verification is false,
	 *            but the result of the test is OK
	 */
	private void performSignVerify(String data, ECPublicKey publicKey,
			ECPrivateKey privateKey, String digestName, String encoder,
			Boolean details, String curveName, Boolean tamperParams) {
		Boolean verifyResult;
		BigInteger[] sign;
		String signStr;
		String res;

		try {
			// Sign using the specified parameters
			sign = asymmetricCryptoUtils.sign(data, privateKey, digestName);
			if (defaultEncoder.equalsIgnoreCase(CryptoUtils.ENCODER_BASE64)) {
				signStr = "r = "
						+ new String(Base64.encode(sign[0].toByteArray()))
						+ " s = "
						+ new String(Base64.encode(sign[1].toByteArray()));
			} else {
				signStr = "r = "
						+ new String(Hex.encode(sign[0].toByteArray()))
						+ " s = "
						+ new String(Hex.encode(sign[1].toByteArray()));
			}

			// Verify using the specified parameters
			verifyResult = asymmetricCryptoUtils.verify(data, sign, publicKey,
					digestName);

			res = verifyResult || tamperParams ? "OK" : "FAIL";

			log.info("[" + curveName + ": " + digestName + " - STR - "
					+ encoder + "] - " + res);
			if (details) {
				log.info("SIGN= " + signStr);
				log.info("VERIFY RES= " + verifyResult);
			}
		} catch (CryptoUtilsException e) {

			log.error("SIGN/VERIFY Error: " + e.getMessage());
		}
	}

	/**
	 * Perform Encrypt/Decrypt test with the input data, in this test data is
	 * encrypted, then decrypted and compared if the result at the end of the
	 * process is the same as the input the result will be OK otherwise FAIL
	 * 
	 * @param data
	 * @param receiverKeys
	 * @param senderKey
	 * @param derivation
	 * @param encoding
	 * @param macSize
	 * @param keySize
	 * @param details
	 * @param curveName
	 */
	private void performEncryptDecrypt(byte[] data, ECKeyPair receiverKeys,
			ECKeyPair senderKey, byte[] derivation, byte[] encoding,
			Integer macSize, Integer keySize, Boolean details, String curveName) {
		List<byte[]> cipher;
		byte[] decipher;

		String cipherStr;
		String decipherStr;
		String res;
		String dataStr;
		if (defaultEncoder.equalsIgnoreCase(CryptoUtils.ENCODER_BASE64)) {
			dataStr = new String(Base64.encode(data));
		} else {
			dataStr = new String(Hex.encode(data));
		}
		try {
			// Encrypt using the specified parameters
			cipher = asymmetricCryptoUtils.encrypt(data,
					receiverKeys.getPublicKey(), senderKey.getPrivateKey(),
					derivation, encoding, macSize, keySize);
			if (defaultEncoder.equalsIgnoreCase(CryptoUtils.ENCODER_BASE64)) {
				cipherStr = new String(Base64.encode(cipher.get(0)));
			} else {
				cipherStr = new String(Hex.encode(cipher.get(0)));
			}

			// Decrypt using the specified parameters
			decipher = asymmetricCryptoUtils.decrypt(cipher.get(0),
					cipher.get(1), senderKey.getPublicKey(),
					receiverKeys.getPrivateKey(), derivation, encoding,
					macSize, keySize);

			if (defaultEncoder.equalsIgnoreCase(CryptoUtils.ENCODER_BASE64)) {
				decipherStr = new String(Base64.encode(decipher));
			} else {
				decipherStr = new String(Hex.encode(decipher));
			}

			res = decipherStr.equalsIgnoreCase(dataStr) ? "OK" : "FAIL";

			log.info("[" + curveName + ": " + macSize + " - " + keySize
					+ " - BYTE" + "] - " + res);
			if (details) {
				log.info("ENCYPTED= " + cipherStr);
				log.info("DECYPTED= " + decipherStr);
			}
		} catch (CryptoUtilsException e) {

			log.error("ENCRYPT/DECRYPT P: " + e.getMessage());
		}
	}

	/**
	 * Perform Encrypt/Decrypt test with the input data, in this test data is
	 * encrypted, then decrypted and compared if the result at the end of the
	 * process is the same as the input the result will be OK otherwise FAIL
	 * 
	 * @param data
	 * @param publicKey
	 * @param privateKey
	 * @param operationMode
	 * @param details
	 * @param primeSize
	 */
	private void performEncryptDecrypt(String data, ECKeyPair receiverKeys,
			ECKeyPair senderKey, byte[] derivation, byte[] encoding,
			Integer macSize, Integer keySize, Boolean details,
			String curveName, String encoder) {
		List<String> cipher;
		String decipher;
		String res;
		// dataStr = new String(Base64.encode(data));
		try {
			// Encrypt using the specified parameters
			cipher = asymmetricCryptoUtils.encrypt(data,
					receiverKeys.getPublicKey(), senderKey.getPrivateKey(),
					derivation, encoding, macSize, keySize, encoder);

			// Decrypt using the specified parameters
			decipher = asymmetricCryptoUtils.decrypt(cipher.get(0),
					cipher.get(1), senderKey.getPublicKey(),
					receiverKeys.getPrivateKey(), derivation, encoding,
					macSize, keySize, encoder);

			// decipherStr = new String(Base64.encode(decipher));
			res = decipher.equalsIgnoreCase(data) ? "OK" : "FAIL";

			log.info("[" + curveName + ": " + macSize + " - " + keySize
					+ ": STR " + encoder + "] - " + res);
			if (details) {
				log.info("ENCYPTED= " + cipher);
				log.info("DECYPTED= " + decipher);
			}
		} catch (CryptoUtilsException e) {

			log.error("ENCRYPT/DECRYPT P: " + e.getMessage());
		}
	}

	/**
	 * In this test a EC key pair is generated, then saved and loaded from a
	 * file finally the loaded key is compared with the original one
	 * 
	 * @param keySize
	 */
	private void testSaveAndLoadKeyFile(String curveName, Boolean detailResult) {
		log.info("[" + curveName + "] ---- SAVE AND LOAD KEY FROM FILE---- ");
		try {
			ECKeyPair key;

			// Generate Key and random input data
			key = asymmetricCryptoUtils.generateKeys(curveName);

			String keyFileName = Environment.getExternalStorageDirectory()
					+ "/cryptoTest/ECkey" + curveName;
			File f = new File(keyFileName);
			if (!f.getParentFile().exists()) {
				f.getParentFile().mkdir();
			}
			if (detailResult)
				log.info("[" + curveName + "] Original KEY= "
						+ key.toString(defaultEncoder));

			// testPKCS8PEMPrivateKey(key, keyFileName, curveName,
			// detailResult);
			// testPKCS8DERPrivateKey(key, keyFileName, curveName,
			// detailResult);
			testPKCS8DERPublicKey(key, keyFileName, curveName, detailResult);

		} catch (CryptoUtilsException e) {
			e.printStackTrace();
			log.error(
					"testSaveAndLoadKeyFile [" + curveName + "]= "
							+ e.getMessage(), e.getCause());
		}
	}

	/**
	 * Timing the process for saving a EC Keys
	 * 
	 * @param keySize
	 */
	private void testSaveAndLoadKeyFileTiming(String curveName) {
		try {

			ECKeyPair key;
			key = asymmetricCryptoUtils.generateKeys(curveName);

			String keyFileName = Environment.getExternalStorageDirectory()
					+ "/cryptoTest/ECkey" + curveName;
			File f = new File(keyFileName);
			if (!f.getParentFile().exists()) {
				f.getParentFile().mkdir();
			}

			testPKCS8DERPublicKeyTiming(key, keyFileName, curveName);
			testPKCS8PEMPrivateKeyTiming(key, keyFileName, curveName);

		} catch (CryptoUtilsException e) {
			e.printStackTrace();
			log.error("TimingSaveAndLoadKeyFile = " + e.getMessage(),
					e.getCause());
			log.toFile("TimingSaveAndLoadKeyFile = " + e.getMessage(),
					logFileName);
		}
	}

	/**
	 * Test save and read the private key in PKCS8 format, will test PEM
	 * encoding as well as encrypted (using different algorithms) and plain
	 * storage
	 * 
	 * @param keyPair
	 *            Key Pair that contains the private key
	 * @param filePath
	 *            File Path in which the keys will be stored
	 * @param curveName
	 * @param detailResult
	 *            If the result should print the details
	 * @throws CryptoUtilsException
	 */
	private void testPKCS8PEMPrivateKey(ECKeyPair keyPair, String filePath,
			String curveName, Boolean detailResult) throws CryptoUtilsException {
		ECPrivateKey privateKeyOriginal = keyPair.getPrivateKey();
		ECPrivateKey privateKeyRecovered;

		String fileSufix = "";
		String algorithm = "";
		String password = "PASSWORD";
		String algorithmName = "";
		String res = "";
		// Start Plain PEM Private Key test
		log.info("[" + curveName + "] - PEM Private Key-");
		fileSufix = "PEM_Priv_Plain.pem";
		privateKeyOriginal.savePKCS8PEM(filePath + fileSufix);

		privateKeyRecovered = ECPrivateKey.loadPKCS8PEM(filePath + fileSufix);

		if (detailResult)
			log.info("[" + curveName + "] Recovered PEM KEY= "
					+ privateKeyRecovered.toString(defaultEncoder));

		res = privateKeyRecovered.equals(privateKeyOriginal) ? "OK" : "FAIL";
		log.info("[" + curveName + "] RES PEM PLAIN= " + res);

		// Start Encrypted PKCS8 PEM Private Key test
		algorithm = CryptoUtils.AES_128_CBC;
		algorithmName = "AES_128_CBC";
		fileSufix = "PEM_Priv_Enc" + algorithmName + ".pem";
		privateKeyOriginal.savePKCS8PEM(filePath + fileSufix, algorithm,
				password);
		privateKeyRecovered = ECPrivateKey.loadPKCS8PEM(filePath + fileSufix,
				password);

		if (detailResult)
			log.info("[" + curveName + "] Recovered PEM - " + algorithmName
					+ " KEY= " + privateKeyRecovered.toString(defaultEncoder));

		res = privateKeyRecovered.equals(privateKeyOriginal) ? "OK" : "FAIL";
		log.info("[" + curveName + "] RES PEM - " + algorithmName + "= " + res);

		algorithm = CryptoUtils.AES_192_CBC;
		algorithmName = "AES_192_CBC";
		fileSufix = "PEM_Priv_Enc" + algorithmName + ".pem";
		privateKeyOriginal.savePKCS8PEM(filePath + fileSufix, algorithm,
				password);
		privateKeyRecovered = ECPrivateKey.loadPKCS8PEM(filePath + fileSufix,
				password);

		if (detailResult)
			log.info("[" + curveName + "] Recovered PEM - " + algorithmName
					+ " KEY= " + privateKeyRecovered.toString(defaultEncoder));
		res = privateKeyRecovered.equals(privateKeyOriginal) ? "OK" : "FAIL";
		log.info("[" + curveName + "] RES PEM - " + algorithmName + "= " + res);

		algorithm = CryptoUtils.AES_256_CBC;
		algorithmName = "AES_256_CBC";
		fileSufix = "PEM_Priv_Enc" + algorithmName + ".pem";
		privateKeyOriginal.savePKCS8PEM(filePath + fileSufix, algorithm,
				password);
		privateKeyRecovered = ECPrivateKey.loadPKCS8PEM(filePath + fileSufix,
				password);

		if (detailResult)
			log.info("[" + curveName + "] Recovered PEM - " + algorithmName
					+ " KEY= " + privateKeyRecovered.toString(defaultEncoder));
		res = privateKeyRecovered.equals(privateKeyOriginal) ? "OK" : "FAIL";
		log.info("[" + curveName + "] RES PEM - " + algorithmName + "= " + res);

		algorithm = CryptoUtils.DES3_CBC;
		algorithmName = "DES3_CBC";
		fileSufix = "PEM_Priv_Enc" + algorithmName + ".pem";
		privateKeyOriginal.savePKCS8PEM(filePath + fileSufix, algorithm,
				password);
		privateKeyRecovered = ECPrivateKey.loadPKCS8PEM(filePath + fileSufix,
				password);

		if (detailResult)
			log.info("[" + curveName + "] Recovered PEM - " + algorithmName
					+ " KEY= " + privateKeyRecovered.toString(defaultEncoder));
		res = privateKeyRecovered.equals(privateKeyOriginal) ? "OK" : "FAIL";
		log.info("[" + curveName + "] RES PEM - " + algorithmName + "= " + res);

		algorithm = CryptoUtils.PBE_SHA1_2DES;
		algorithmName = "PBE_SHA1_2DES";
		fileSufix = "PEM_Priv_Enc" + algorithmName + ".pem";
		privateKeyOriginal.savePKCS8PEM(filePath + fileSufix, algorithm,
				password);
		privateKeyRecovered = ECPrivateKey.loadPKCS8PEM(filePath + fileSufix,
				password);

		if (detailResult)
			log.info("[" + curveName + "] Recovered PEM - " + algorithmName
					+ " KEY= " + privateKeyRecovered.toString(defaultEncoder));
		res = privateKeyRecovered.equals(privateKeyOriginal) ? "OK" : "FAIL";
		log.info("[" + curveName + "] RES PEM - " + algorithmName + "= " + res);

		algorithm = CryptoUtils.PBE_SHA1_3DES;
		algorithmName = "PBE_SHA1_3DES";
		fileSufix = "PEM_Priv_Enc" + algorithmName + ".pem";
		privateKeyOriginal.savePKCS8PEM(filePath + fileSufix, algorithm,
				password);
		privateKeyRecovered = ECPrivateKey.loadPKCS8PEM(filePath + fileSufix,
				password);

		if (detailResult)
			log.info("[" + curveName + "] Recovered PEM - " + algorithmName
					+ " KEY= " + privateKeyRecovered.toString(defaultEncoder));
		res = privateKeyRecovered.equals(privateKeyOriginal) ? "OK" : "FAIL";
		log.info("[" + curveName + "] RES PEM - " + algorithmName + "= " + res);

		algorithm = CryptoUtils.PBE_SHA1_RC2_128;
		algorithmName = "PBE_SHA1_RC2_128";
		fileSufix = "PEM_Priv_Enc" + algorithmName + ".pem";
		privateKeyOriginal.savePKCS8PEM(filePath + fileSufix, algorithm,
				password);
		privateKeyRecovered = ECPrivateKey.loadPKCS8PEM(filePath + fileSufix,
				password);

		if (detailResult)
			log.info("[" + curveName + "] Recovered PEM - " + algorithmName
					+ " KEY= " + privateKeyRecovered.toString(defaultEncoder));
		res = privateKeyRecovered.equals(privateKeyOriginal) ? "OK" : "FAIL";
		log.info("[" + curveName + "] RES PEM - " + algorithmName + "= " + res);

		algorithm = CryptoUtils.PBE_SHA1_RC2_40;
		algorithmName = "PBE_SHA1_RC2_40";
		fileSufix = "PEM_Priv_Enc" + algorithmName + ".pem";
		privateKeyOriginal.savePKCS8PEM(filePath + fileSufix, algorithm,
				password);
		privateKeyRecovered = ECPrivateKey.loadPKCS8PEM(filePath + fileSufix,
				password);

		if (detailResult)
			log.info("[" + curveName + "] Recovered PEM - " + algorithmName
					+ " KEY= " + privateKeyRecovered.toString(defaultEncoder));
		res = privateKeyRecovered.equals(privateKeyOriginal) ? "OK" : "FAIL";
		log.info("[" + curveName + "] RES PEM - " + algorithmName + "= " + res);

		algorithm = CryptoUtils.PBE_SHA1_RC4_128;
		algorithmName = "PBE_SHA1_RC4_128";
		fileSufix = "PEM_Priv_Enc" + algorithmName + ".pem";
		privateKeyOriginal.savePKCS8PEM(filePath + fileSufix, algorithm,
				password);
		privateKeyRecovered = ECPrivateKey.loadPKCS8PEM(filePath + fileSufix,
				password);

		if (detailResult)
			log.info("[" + curveName + "] Recovered PEM - " + algorithmName
					+ " KEY= " + privateKeyRecovered.toString(defaultEncoder));
		res = privateKeyRecovered.equals(privateKeyOriginal) ? "OK" : "FAIL";
		log.info("[" + curveName + "] RES PEM - " + algorithmName + "= " + res);

		algorithm = CryptoUtils.PBE_SHA1_RC4_40;
		algorithmName = "PBE_SHA1_RC4_40";
		fileSufix = "PEM_Priv_Enc" + algorithmName + ".pem";
		privateKeyOriginal.savePKCS8PEM(filePath + fileSufix, algorithm,
				password);
		privateKeyRecovered = ECPrivateKey.loadPKCS8PEM(filePath + fileSufix,
				password);

		if (detailResult)
			log.info("[" + curveName + "] Recovered PEM - " + algorithmName
					+ " KEY= " + privateKeyRecovered.toString(defaultEncoder));
		res = privateKeyRecovered.equals(privateKeyOriginal) ? "OK" : "FAIL";
		log.info("[" + curveName + "] RES PEM - " + algorithmName + "= " + res);

	}

	/**
	 * Test save and read the private key in PKCS8 format, will test DER
	 * encoding as well as encrypted (using different algorithms) and plain
	 * storage
	 * 
	 * @param keyPair
	 *            Key Pair that contains the private key
	 * @param filePath
	 *            File Path in which the keys will be stored
	 * @param curveName
	 * @param detailResult
	 *            If the result should print the details
	 * @throws CryptoUtilsException
	 */
	private void testPKCS8DERPrivateKey(ECKeyPair keyPair, String filePath,
			String curveName, Boolean detailResult) throws CryptoUtilsException {
		ECPrivateKey privateKeyOriginal = keyPair.getPrivateKey();
		ECPrivateKey privateKeyRecovered;

		String fileSufix = "";
		String algorithm = "";
		String password = "PASSWORD";
		String algorithmName = "";
		String res = "";
		// Start Plain PEM Private Key test
		log.info("[" + curveName + "] - DER Private Key-");
		fileSufix = "DER_Priv_Plain.der";
		privateKeyOriginal.savePKCS8DER(filePath + fileSufix);

		privateKeyRecovered = ECPrivateKey.loadPKCS8DER(filePath + fileSufix);

		if (detailResult)
			log.info("[" + curveName + "] Recovered DER KEY= "
					+ privateKeyRecovered.toString(defaultEncoder));

		res = privateKeyRecovered.equals(privateKeyOriginal) ? "OK" : "FAIL";
		log.info("[" + curveName + "] RES DER PLAIN= " + res);

		// Start Encrypted PKCS8 PEM Private Key test
		/*
		 * algorithm = ECPrivateKey.AES_128_CBC; algorithmName = "AES_128_CBC";
		 * fileSufix = "DER_Priv_Enc" + algorithmName + ".der";
		 * privateKeyOriginal.savePKCS8DER(filePath + fileSufix, algorithm,
		 * password);
		 * 
		 * //privateKeyRecovered.readPKCS8DER(filePath + fileSufix, password);
		 * privateKeyRecovered
		 * .readPKCS8DER(Environment.getExternalStorageDirectory() +
		 * "/cryptoTest/pkcs8v2_rsa_aes128_cbc.der", password);
		 */

		/*
		 * if (detailResult) log.info("[" + primeSize + "] Recovered PEM - " +
		 * algorithmName + " KEY= " +
		 * privateKeyRecovered.toString(defaultEncoder));
		 * 
		 * res = privateKeyRecovered.equals(privateKeyOriginal) ? "OK" : "FAIL";
		 * log.info("[" + primeSize + "] RES PEM - " + algorithmName + "= " +
		 * res);
		 * 
		 * algorithm = RSAPrivateKey.AES_192_CBC; algorithmName = "AES_192_CBC";
		 * fileSufix = "PEM_Priv_Enc" + algorithmName + ".pem";
		 * privateKeyOriginal.savePKCS8PEM(filePath + fileSufix, algorithm,
		 * password); privateKeyRecovered.readPKCS8PEM(filePath + fileSufix,
		 * password);
		 * 
		 * if (detailResult) log.info("[" + primeSize + "] Recovered PEM - " +
		 * algorithmName + " KEY= " +
		 * privateKeyRecovered.toString(defaultEncoder)); res =
		 * privateKeyRecovered.equals(privateKeyOriginal) ? "OK" : "FAIL";
		 * log.info("[" + primeSize + "] RES PEM - " + algorithmName + "= " +
		 * res);
		 * 
		 * algorithm = RSAPrivateKey.AES_256_CBC; algorithmName = "AES_256_CBC";
		 * fileSufix = "PEM_Priv_Enc" + algorithmName + ".pem";
		 * privateKeyOriginal.savePKCS8PEM(filePath + fileSufix, algorithm,
		 * password); privateKeyRecovered.readPKCS8PEM(filePath + fileSufix,
		 * password);
		 * 
		 * if (detailResult) log.info("[" + primeSize + "] Recovered PEM - " +
		 * algorithmName + " KEY= " +
		 * privateKeyRecovered.toString(defaultEncoder)); res =
		 * privateKeyRecovered.equals(privateKeyOriginal) ? "OK" : "FAIL";
		 * log.info("[" + primeSize + "] RES PEM - " + algorithmName + "= " +
		 * res);
		 * 
		 * algorithm = RSAPrivateKey.DES3_CBC; algorithmName = "DES3_CBC";
		 * fileSufix = "PEM_Priv_Enc" + algorithmName + ".pem";
		 * privateKeyOriginal.savePKCS8PEM(filePath + fileSufix, algorithm,
		 * password); privateKeyRecovered.readPKCS8PEM(filePath + fileSufix,
		 * password);
		 * 
		 * if (detailResult) log.info("[" + primeSize + "] Recovered PEM - " +
		 * algorithmName + " KEY= " +
		 * privateKeyRecovered.toString(defaultEncoder)); res =
		 * privateKeyRecovered.equals(privateKeyOriginal) ? "OK" : "FAIL";
		 * log.info("[" + primeSize + "] RES PEM - " + algorithmName + "= " +
		 * res);
		 * 
		 * algorithm = RSAPrivateKey.PBE_SHA1_2DES; algorithmName =
		 * "PBE_SHA1_2DES"; fileSufix = "PEM_Priv_Enc" + algorithmName + ".pem";
		 * privateKeyOriginal.savePKCS8PEM(filePath + fileSufix, algorithm,
		 * password); privateKeyRecovered.readPKCS8PEM(filePath + fileSufix,
		 * password);
		 * 
		 * if (detailResult) log.info("[" + primeSize + "] Recovered PEM - " +
		 * algorithmName + " KEY= " +
		 * privateKeyRecovered.toString(defaultEncoder)); res =
		 * privateKeyRecovered.equals(privateKeyOriginal) ? "OK" : "FAIL";
		 * log.info("[" + primeSize + "] RES PEM - " + algorithmName + "= " +
		 * res);
		 * 
		 * algorithm = RSAPrivateKey.PBE_SHA1_3DES; algorithmName =
		 * "PBE_SHA1_3DES"; fileSufix = "PEM_Priv_Enc" + algorithmName + ".pem";
		 * privateKeyOriginal.savePKCS8PEM(filePath + fileSufix, algorithm,
		 * password); privateKeyRecovered.readPKCS8PEM(filePath + fileSufix,
		 * password);
		 * 
		 * if (detailResult) log.info("[" + primeSize + "] Recovered PEM - " +
		 * algorithmName + " KEY= " +
		 * privateKeyRecovered.toString(defaultEncoder)); res =
		 * privateKeyRecovered.equals(privateKeyOriginal) ? "OK" : "FAIL";
		 * log.info("[" + primeSize + "] RES PEM - " + algorithmName + "= " +
		 * res);
		 * 
		 * algorithm = RSAPrivateKey.PBE_SHA1_RC2_128; algorithmName =
		 * "PBE_SHA1_RC2_128"; fileSufix = "PEM_Priv_Enc" + algorithmName +
		 * ".pem"; privateKeyOriginal.savePKCS8PEM(filePath + fileSufix,
		 * algorithm, password); privateKeyRecovered.readPKCS8PEM(filePath +
		 * fileSufix, password);
		 * 
		 * if (detailResult) log.info("[" + primeSize + "] Recovered PEM - " +
		 * algorithmName + " KEY= " +
		 * privateKeyRecovered.toString(defaultEncoder)); res =
		 * privateKeyRecovered.equals(privateKeyOriginal) ? "OK" : "FAIL";
		 * log.info("[" + primeSize + "] RES PEM - " + algorithmName + "= " +
		 * res);
		 * 
		 * algorithm = RSAPrivateKey.PBE_SHA1_RC2_40; algorithmName =
		 * "PBE_SHA1_RC2_40"; fileSufix = "PEM_Priv_Enc" + algorithmName +
		 * ".pem"; privateKeyOriginal.savePKCS8PEM(filePath + fileSufix,
		 * algorithm, password); privateKeyRecovered.readPKCS8PEM(filePath +
		 * fileSufix, password);
		 * 
		 * if (detailResult) log.info("[" + primeSize + "] Recovered PEM - " +
		 * algorithmName + " KEY= " +
		 * privateKeyRecovered.toString(defaultEncoder)); res =
		 * privateKeyRecovered.equals(privateKeyOriginal) ? "OK" : "FAIL";
		 * log.info("[" + primeSize + "] RES PEM - " + algorithmName + "= " +
		 * res);
		 * 
		 * algorithm = RSAPrivateKey.PBE_SHA1_RC4_128; algorithmName =
		 * "PBE_SHA1_RC4_128"; fileSufix = "PEM_Priv_Enc" + algorithmName +
		 * ".pem"; privateKeyOriginal.savePKCS8PEM(filePath + fileSufix,
		 * algorithm, password); privateKeyRecovered.readPKCS8PEM(filePath +
		 * fileSufix, password);
		 * 
		 * if (detailResult) log.info("[" + primeSize + "] Recovered PEM - " +
		 * algorithmName + " KEY= " +
		 * privateKeyRecovered.toString(defaultEncoder)); res =
		 * privateKeyRecovered.equals(privateKeyOriginal) ? "OK" : "FAIL";
		 * log.info("[" + primeSize + "] RES PEM - " + algorithmName + "= " +
		 * res);
		 * 
		 * algorithm = RSAPrivateKey.PBE_SHA1_RC4_40; algorithmName =
		 * "PBE_SHA1_RC4_40"; fileSufix = "PEM_Priv_Enc" + algorithmName +
		 * ".pem"; privateKeyOriginal.savePKCS8PEM(filePath + fileSufix,
		 * algorithm, password); privateKeyRecovered.readPKCS8PEM(filePath +
		 * fileSufix, password);
		 * 
		 * if (detailResult) log.info("[" + primeSize + "] Recovered PEM - " +
		 * algorithmName + " KEY= " +
		 * privateKeyRecovered.toString(defaultEncoder)); res =
		 * privateKeyRecovered.equals(privateKeyOriginal) ? "OK" : "FAIL";
		 * log.info("[" + primeSize + "] RES PEM - " + algorithmName + "= " +
		 * res);
		 */
	}

	/**
	 * Test save and read the private key in PKCS8 format, will test DER
	 * encoding as well as encrypted (using different algorithms) and plain
	 * storage
	 * 
	 * @param keyPair
	 *            Key Pair that contains the private key
	 * @param filePath
	 *            File Path in which the keys will be stored
	 * @param curveName
	 * @param detailResult
	 *            If the result should print the details
	 * @throws CryptoUtilsException
	 */
	private void testPKCS8DERPublicKey(ECKeyPair keyPair, String filePath,
			String curveName, Boolean detailResult) throws CryptoUtilsException {
		ECPublicKey publicKeyOriginal = keyPair.getPublicKey();
		ECPublicKey publicKeyRecovered;

		String fileSufix = "";
		String algorithm = "";
		String password = "PASSWORD";
		String algorithmName = "";
		String res = "";
		// Start Plain PEM Private Key test
		log.info("[" + curveName + "] - DER Public Key-");
		fileSufix = "DER_Pub_Plain.der";
		publicKeyOriginal.saveDER(filePath + fileSufix);

		publicKeyRecovered = ECPublicKey.loadDER(filePath + fileSufix);

		if (detailResult)
			log.info("[" + curveName + "] Recovered DER KEY= "
					+ publicKeyRecovered.toString(defaultEncoder));

		res = publicKeyRecovered.equals(publicKeyOriginal) ? "OK" : "FAIL";
		log.info("[" + curveName + "] RES DER PLAIN= " + res);
	}

	/**
	 * Timing save and read the private key in PKCS8 format, will test DER
	 * encoding
	 * 
	 * @param keyPair
	 *            Key Pair that contains the private key
	 * @param filePath
	 *            File Path in which the keys will be stored
	 * @param curveName
	 * @param detailResult
	 *            If the result should print the details
	 * @throws CryptoUtilsException
	 */
	private void testPKCS8DERPublicKeyTiming(ECKeyPair keyPair,
			String filePath, String curveName) throws CryptoUtilsException {
		ECPublicKey publicKeyOriginal = keyPair.getPublicKey();

		String fileSufix = "";

		fileSufix = "DER_Pub.der";

		long startnow;
		long endnow;
		long total = 0;
		long startnowAux;
		long endnowAux;
		long totalAux = 0;
		int totalRounds = 100;

		try {
			for (int i = 0; i < totalRounds; i++) {
				for (int j = 0; j < totalRounds; j++) {
					// Start Plain DER Public Key test
					startnow = java.lang.System.nanoTime();
					publicKeyOriginal.saveDER(filePath + fileSufix);
					endnow = java.lang.System.nanoTime();
					total += (endnow - startnow);

					startnowAux = java.lang.System.nanoTime();
					ECPublicKey.loadDER(filePath + fileSufix);
					endnowAux = java.lang.System.nanoTime();
					totalAux += (endnowAux - startnowAux);
				}
			}

			String totalStr = "[" + curveName + "] PUBLIC DER SAVE= "
					+ (total / (totalRounds * totalRounds * 1.0));
			String totalAuxStr = "[" + curveName + "] PUBLIC DER LOAD= "
					+ (totalAux / (totalRounds * totalRounds * 1.0));
			log.info(totalStr);
			log.toFile(totalStr, logFileName);
			log.info(totalAuxStr);
			log.toFile(totalAuxStr, logFileName);
		} catch (CryptoUtilsException e) {

			log.error(
					"KeyGen [" + curveName + "]= SAVE/LOAD DER PUBLIC: "
							+ e.getMessage(), e.getCause());
			log.toFile(
					"KeyGen [" + curveName + "]= SAVE/LOAD DER PUBLIC: "
							+ e.getMessage(), logFileName);
		}
	}

	/**
	 * In this test a EC key pair is generated, then encoded and decoded,
	 * finally the decoded key is compared with the original one
	 * 
	 * @param keySize
	 */
	private void testEncodeDecodeKey(String curveName, Boolean detailResult) {
		log.info("[" + curveName + "] ---- ENCODE AND DECODE KEY ---- ");
		try {
			ECKeyPair key;
			ECPrivateKey resPrivateKey;
			ECPublicKey resPublicKey;
			ECKeyPair resKey;
			String res;

			// Generate Key and random input data
			key = asymmetricCryptoUtils.generateKeys(curveName);
			String password = "PASSWORD";
			// String keyStr = "";
			byte[] keyBytes;

			if (detailResult)
				log.info("[" + curveName + "] Original KEY= "
						+ key.toString(defaultEncoder));

			// Start ENCODE - DECODE Public Key test
			keyBytes = key.getPublicKey().encode();
			// keyStr = new String(keyBytes);
			resPublicKey = ECPublicKey.decode(keyBytes);

			if (detailResult)
				log.info("[" + curveName + "] Recovered Public KEY= "
						+ resPublicKey.toString(defaultEncoder));

			res = resPublicKey.equals(key.getPublicKey()) ? "OK" : "FAIL";
			log.info("[" + curveName + "] RES PUBLIC KEY= " + res);

			// Start ENCODE - DECODE PKCS12 test
			Date notBefore = new Date(System.currentTimeMillis() - 1000L * 60
					* 60 * 24 * 30);
			Date notAfter = new Date(System.currentTimeMillis() + 1000L * 60
					* 60 * 24 * 30);

			Certificate[] chain;

			List<Integer> keyUsageList;
			String certType;
			certType = X509UtilsDictionary.CERTIFICATE_TYPE_ROOT_CA;
			keyUsageList = new LinkedList<Integer>();
			keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_CRL_SIGN);
			keyUsageList
					.add(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT);
			keyUsageList
					.add(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE);
			keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_CERT_SIGN);
			keyUsageList
					.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT);

			HashMap<String, String> subject1CertificateInformationMap = new HashMap<String, String>();
			subject1CertificateInformationMap.put(
					CertificateInformationKeys.FRIENDLY_NAME, "Subject1");
			subject1CertificateInformationMap.put(
					CertificateInformationKeys.COUNTRY, "MX");
			subject1CertificateInformationMap.put(
					CertificateInformationKeys.EmailAddress,
					"subject1@gmail.com");
			subject1CertificateInformationMap.put(
					CertificateInformationKeys.FULL_COMMON_NAME,
					"Subject1 Name Master");
			subject1CertificateInformationMap.put(
					CertificateInformationKeys.LOCALITY, "GAM");
			subject1CertificateInformationMap.put(
					CertificateInformationKeys.STATE, "DF");
			subject1CertificateInformationMap.put(
					CertificateInformationKeys.ORGANIZATION, "Cinvestav");
			// Creates Root CA self signed certificate
			chain = new Certificate[1];
			chain[0] = _X509Utils.createV3Cert(key.getPublicKey(),
					key.getPrivateKey(), BigInteger.valueOf(1), notBefore,
					notAfter, subject1CertificateInformationMap, keyUsageList,
					certType,
					X509UtilsDictionary.EC_X509_SIGN_ALGORITHM_SHA1withECDSA);

			keyBytes = key.encodePKCS12(password, password, chain);
			// keyStr = new String(keyBytes);
			Object resEncoded[] = ECKeyPair.decodePKCS12(keyBytes, password,
					password);
			resKey = (ECKeyPair) resEncoded[0];

			if (detailResult)
				log.info("[" + curveName + "] Recovered Key Pair= "
						+ resKey.toString(defaultEncoder));

			res = resKey.equals(key) ? "OK" : "FAIL";
			log.info("[" + curveName + "] RES KEY PAIR= " + res);

		} catch (CryptoUtilsException e) { // TODO Auto-generated catch
											// block
			e.printStackTrace();
			log.error(
					"testEncodeDecodeKey [" + curveName + "]= "
							+ e.getMessage(), e.getCause());
		} catch (CryptoUtilsX509ExtensionException e) {
			log.error(
					"testEncodeDecodeKey [" + curveName + "]= "
							+ e.getMessage(), e.getCause());
		}
	}

	/**
	 * Timing save and read the private key in PKCS8 format, will test PEM
	 * encoding as well as encrypted (using different algorithms) and plain
	 * storage
	 * 
	 * @param keyPair
	 *            Key Pair that contains the private key
	 * @param filePath
	 *            File Path in which the keys will be stored
	 * @param primeSize
	 * @param detailResult
	 *            If the result should print the details
	 * @throws CryptoUtilsException
	 */
	private void testPKCS8PEMPrivateKeyTiming(ECKeyPair keyPair,
			String filePath, String curveName) throws CryptoUtilsException {
		ECPrivateKey privateKeyOriginal = keyPair.getPrivateKey();

		String fileSufix = "";
		String algorithm = "";
		String password = "PASSWORD";
		long startnow;
		long endnow;
		long total = 0;
		long startnowAux;
		long endnowAux;
		long totalAux = 0;
		int totalRounds = 50;
		String totalStr = "";
		String totalAuxStr = "";

		fileSufix = "PEM_Priv_Plain.pem";

		for (int i = 0; i < totalRounds; i++) {
			for (int j = 0; j < totalRounds; j++) {
				// Start Plain PEM Private Key timing
				startnow = java.lang.System.nanoTime();
				privateKeyOriginal.savePKCS8PEM(filePath + fileSufix);
				endnow = java.lang.System.nanoTime();
				total += (endnow - startnow);

				startnowAux = java.lang.System.nanoTime();
				ECPrivateKey.loadPKCS8PEM(filePath + fileSufix);
				endnowAux = java.lang.System.nanoTime();
				totalAux += (endnowAux - startnowAux);
			}
		}

		totalStr = "[" + curveName + "] PRIVATE PEM PLAIN SAVE= "
				+ (total / (totalRounds * totalRounds * 1.0));
		totalAuxStr = "[" + curveName + "] PRIVATE PEM PLAIN LOAD= "
				+ (totalAux / (totalRounds * totalRounds * 1.0));
		log.info(totalStr);
		log.toFile(totalStr, logFileName);
		log.info(totalAuxStr);
		log.toFile(totalAuxStr, logFileName);

		// Create available algorithms array
		String[] availableAlgorithm = { CryptoUtils.AES_256_CBC,
				CryptoUtils.PBE_SHA1_3DES };
		int selectedAlgorithm;

		totalRounds = 10;
		for (selectedAlgorithm = 0; selectedAlgorithm < 2; selectedAlgorithm++) {
			// Restart counters
			startnow = 0;
			endnow = 0;
			total = 0;
			startnowAux = 0;
			endnowAux = 0;
			totalAux = 0;
			totalStr = "";
			totalAuxStr = "";
			algorithm = availableAlgorithm[selectedAlgorithm];
			for (int i = 0; i < totalRounds; i++) {
				for (int j = 0; j < totalRounds; j++) {
					// Start Plain PEM Private Key timing
					startnow = java.lang.System.nanoTime();
					privateKeyOriginal.savePKCS8PEM(filePath + fileSufix,
							algorithm, password);
					endnow = java.lang.System.nanoTime();
					total += (endnow - startnow);

					startnowAux = java.lang.System.nanoTime();
					ECPrivateKey.loadPKCS8PEM(filePath + fileSufix, password);
					endnowAux = java.lang.System.nanoTime();
					totalAux += (endnowAux - startnowAux);
				}
			}

			totalStr = "[" + curveName + "] PRIVATE PEM " + algorithm
					+ " SAVE= " + (total / (totalRounds * totalRounds * 1.0));
			totalAuxStr = "[" + curveName + "] PRIVATE PEM " + algorithm
					+ " LOAD= "
					+ (totalAux / (totalRounds * totalRounds * 1.0));
			log.info(totalStr);
			log.toFile(totalStr, logFileName);
			log.info(totalAuxStr);
			log.toFile(totalAuxStr, logFileName);
		}

	}

	private void testEncryptDecryptRandomTiming(String curveName, int inputSize) {

		ECKeyPair key;
		Integer macSize = 256;
		Integer keySize = 256;

		byte[] derivation = new byte[20];
		byte[] encoding = new byte[20];

		rand.nextBytes(derivation);
		rand.nextBytes(encoding);

		// Generate Key and random input data
		try {
			key = asymmetricCryptoUtils.generateKeys(curveName);

			// Perform Test EncryptDecryptTest
			performEncryptDecryptTiming(inputSize, key, key, derivation,
					encoding, macSize, keySize, curveName);

		} catch (CryptoUtilsException e) {
			log.error(
					"[" + curveName + "]= ENCRYPT/DECRYPT -" + e.getMessage(),
					e.getCause());

		}

	}

	private void testSignVerifyRandomTiming(String curveName, int inputSize) {

		ECKeyPair key;

		// Generate Key and random input data
		try {
			key = asymmetricCryptoUtils.generateKeys(curveName);

			String[] availableDigest = { CryptoUtils.DIGEST_FUNCTION_SHA_1,
					CryptoUtils.DIGEST_FUNCTION_SHA_256,
					CryptoUtils.DIGEST_FUNCTION_SHA_512,
					CryptoUtils.DIGEST_FUNCTION_MD5,
					CryptoUtils.DIGEST_FUNCTION_RIPEMD160 };

			for (int selectedDigest = 0; selectedDigest < availableDigest.length; selectedDigest++) {
				// Perform the sign / verify timing using a random digest
				performSignVerifyTiming(inputSize, key.getPublicKey(),
						key.getPrivateKey(), availableDigest[selectedDigest],
						curveName);
			}

		} catch (CryptoUtilsException e) {
			log.error(
					"[" + curveName + "]= ENCRYPT/DECRYPT -" + e.getMessage(),
					e.getCause());

		}

	}

	/**
	 * Timing Encrypt/Decrypt test with the input data, in this test data is
	 * encrypted, then decrypted and compared if the result at the end of the
	 * process is the same as the input the result will be OK otherwise FAIL
	 * 
	 * @param data
	 * @param receiverKeys
	 * @param senderKey
	 * @param derivation
	 * @param encoding
	 * @param macSize
	 * @param keySize
	 * @param details
	 * @param curveName
	 */
	private void performEncryptDecryptTiming(int inputSize,
			ECKeyPair receiverKeys, ECKeyPair senderKey, byte[] derivation,
			byte[] encoding, Integer macSize, Integer keySize, String curveName) {
		List<byte[]> cipher;

		byte[] data = new byte[inputSize];
		long startnow;
		long endnow;
		long total = 0;
		long startnowAux;
		long endnowAux;
		long totalAux = 0;
		int totalRounds = 15;

		for (int i = 0; i < totalRounds; i++) {
			rand.nextBytes(data);
			for (int j = 0; j < totalRounds; j++) {
				// Encrypt using the specified parameters
				try {
					startnow = java.lang.System.nanoTime();
					cipher = asymmetricCryptoUtils.encrypt(data,
							receiverKeys.getPublicKey(),
							senderKey.getPrivateKey(), derivation, encoding,
							macSize, keySize);

					endnow = java.lang.System.nanoTime();
					total += (endnow - startnow);

					startnowAux = java.lang.System.nanoTime();
					// Decrypt using the specified parameters
					asymmetricCryptoUtils.decrypt(cipher.get(0), cipher.get(1),
							senderKey.getPublicKey(),
							receiverKeys.getPrivateKey(), derivation, encoding,
							macSize, keySize);
					endnowAux = java.lang.System.nanoTime();
					totalAux += (endnowAux - startnowAux);

				} catch (CryptoUtilsException e) {
					log.error("[" + curveName + "]= ENCRYPT/DECRYPT -" + ": "
							+ e.getMessage(), e.getCause());
					log.toFile("[" + curveName + " - " + inputSize
							+ "]= ENCRYPT/DECRYPT -" + ": " + e.getMessage(),
							logFileName);
				}
			}
		}

		String totalStr = "[" + curveName + " - " + inputSize + "] ENCRIPT EC"
				+ "= " + (total / (totalRounds * totalRounds * 1.0));
		String totalAuxStr = "[" + curveName + " - " + inputSize
				+ "] DECRIPT EC" + "= "
				+ (totalAux / (totalRounds * totalRounds * 1.0));
		log.info(totalStr);
		log.toFile(totalStr, logFileName);
		log.info(totalAuxStr);
		log.toFile(totalAuxStr, logFileName);

	}

	/**
	 * Timing the signing of a message and the verification of that signature
	 * and determine if its correct or not
	 * 
	 * @param data
	 *            Data to be signed
	 * @param publicKey
	 *            Public key to verify the sign
	 * @param privateKey
	 *            Private Key to sign the data
	 * @param digestName
	 *            name of the digest Function to use in the signature
	 * @param primeSize
	 *            The key prime size that is been using in this test
	 */
	private void performSignVerifyTiming(int inputSize, ECPublicKey publicKey,
			ECPrivateKey privateKey, String digestName, String curveName) {
		BigInteger[] sign;

		byte[] data = new byte[inputSize];
		long startnow;
		long endnow;
		long total = 0;
		long startnowAux;
		long endnowAux;
		long totalAux = 0;
		int totalRounds = 20;

		for (int i = 0; i < totalRounds; i++) {
			rand.nextBytes(data);
			for (int j = 0; j < totalRounds; j++) {

				try {
					startnow = java.lang.System.nanoTime();
					// Sign using the specified parameters
					sign = asymmetricCryptoUtils.sign(data, privateKey,
							digestName);
					endnow = java.lang.System.nanoTime();
					total += (endnow - startnow);

					startnowAux = java.lang.System.nanoTime();
					// Verify using the specified parameters
					asymmetricCryptoUtils.verify(data, sign, publicKey,
							digestName);
					endnowAux = java.lang.System.nanoTime();
					totalAux += (endnowAux - startnowAux);

				} catch (CryptoUtilsException e) {
					log.error("[" + curveName + "]= SIGN/VERIFY-" + digestName
							+ ": " + e.getMessage(), e.getCause());
					log.toFile(
							"[" + curveName + " - " + inputSize
									+ "]= SIGN/VERIFY -" + digestName + ": "
									+ e.getMessage(), logFileName);
				}
			}
		}

		String totalStr = "[" + curveName + " - " + inputSize + "] SIGN EC-"
				+ digestName + "= "
				+ (total / (totalRounds * totalRounds * 1.0));
		String totalAuxStr = "[" + curveName + " - " + inputSize
				+ "] Verify EC-" + digestName + "= "
				+ (totalAux / (totalRounds * totalRounds * 1.0));
		log.info(totalStr);
		log.toFile(totalStr, logFileName);
		log.info(totalAuxStr);
		log.toFile(totalAuxStr, logFileName);

	}
}
